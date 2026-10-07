#!/usr/bin/env python3
"""TurtleBlock Home v1.0.0 - netzwerkweiter DNS-Filter mit Adblocker-Pro-DNA.

Nur Python-Stdlib, keine externen Pakete. Bietet:
  - DNS-Server (UDP + TCP, Port 53) mit Sinkhole 0.0.0.0 / :: fuer Werbung,
    Tracker, Social-/Consent-Skripte und Hersteller-Telemetrie
  - Web-UI + JSON-API (Port 8196): 3 Module einzeln schaltbar, eigene Filter,
    Ausnahmeliste (Allowlist), Statistiken, Top-Hosts, Domain-Test
  - LAN-Schutz: lokale Namen (.local, .lan, umbrel, fritz.box, ...) werden
    grundsätzlich nie blockiert (Erkenntnis aus rules/lan-allow.json)
  - Surrogat-Prinzip der Extension auf DNS übertragen: sanftes Sinkhole
    statt NXDOMAIN, damit Apps nicht hart abstürzen

Blocklisten in ./lists/*.txt stammen aus der Adblocker-Pro-Extension v2.10.0
(turtlecute/superlist/easylist/easyprivacy/annoyances/url-patterns).
Subdomains werden automatisch mit blockiert (wie AdGuard "||domain^").
"""
import json
import os
import signal
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
WEB_PORT = int(os.environ.get("WEB_PORT", "8196"))
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))
UPSTREAMS = [u for u in os.environ.get("UPSTREAMS", "1.1.1.1 8.8.8.8").split() if u]
ROUTER_IP = os.environ.get("ROUTER_IP", "").strip()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "") or os.environ.get("APP_PASSWORD", "")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
TTL = 300

# --- LAN-Schutz (aus rules/lan-allow.json + Router-/Umbrel-Namen) ---
LAN_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".home.arpa",
                ".home", ".priv", ".corp")
LAN_EXACT = {"localhost", "umbrel", "fritz.box", "router", "gateway", "nas"}


def load_list(fname):
    path = os.path.join(APP_DIR, "lists", fname)
    out = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                out.add(line)
    except OSError as exc:
        print("WARN: Liste %s fehlt (%s)" % (fname, exc), flush=True)
    print("Liste %s: %d Domains" % (fname, len(out)), flush=True)
    return out


ADS = load_list("ads.txt")
TRACKING = load_list("tracking.txt")
ANNOY = load_list("annoyances.txt")

_lock = threading.Lock()
_state = {
    "modules": {"ads": True, "tracking": True, "annoyances": True},
    "custom": [],
    "allow": [],
    "stats": {"queries": 0, "blocked": 0, "hosts": {}, "recent": []},
}


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    with _lock:
        mods = data.get("modules", {})
        for key in ("ads", "tracking", "annoyances"):
            if key in mods:
                _state["modules"][key] = bool(mods[key])
        if isinstance(data.get("custom"), list):
            _state["custom"] = [str(x).lower() for x in data["custom"]][:500]
        if isinstance(data.get("allow"), list):
            _state["allow"] = [str(x).lower() for x in data["allow"]][:500]
        stats = data.get("stats", {})
        try:
            _state["stats"]["queries"] = int(stats.get("queries", 0))
            _state["stats"]["blocked"] = int(stats.get("blocked", 0))
        except (TypeError, ValueError):
            pass
        if isinstance(stats.get("hosts"), dict):
            _state["stats"]["hosts"] = {str(k): int(v) for k, v in
                                        list(stats["hosts"].items())[:800]}


def save_state():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with _lock:
            data = {
                "modules": dict(_state["modules"]),
                "custom": list(_state["custom"]),
                "allow": list(_state["allow"]),
                "stats": {
                    "queries": _state["stats"]["queries"],
                    "blocked": _state["stats"]["blocked"],
                    "hosts": dict(_state["stats"]["hosts"]),
                },
            }
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, STATE_FILE)
    except OSError as exc:
        print("WARN: Speichern fehlgeschlagen: %s" % exc, flush=True)


def match_suffix(name, domain):
    return name == domain or name.endswith("." + domain)


def decide(name):
    """Gibt (blocked, grund) zurück. grund: lan/allow/custom/ads/
    tracking/annoyances/off/ok/invalid."""
    name = (name or "").strip().lower().rstrip(".")
    if not name:
        return False, "invalid"
    if "." not in name:
        return False, "lan"
    if name in LAN_EXACT:
        return False, "lan"
    if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
        return False, "lan"
    for suffix in LAN_SUFFIXES:
        if name.endswith(suffix):
            return False, "lan"
    with _lock:
        allow = list(_state["allow"])
        custom = list(_state["custom"])
        mods = dict(_state["modules"])
    for entry in allow:
        entry = entry.strip().lower()
        if entry and match_suffix(name, entry):
            return False, "allow"
    for entry in custom:
        entry = entry.strip().lower()
        if entry and entry in name:
            return True, "custom"
    if mods.get("ads") and any(match_suffix(name, d) for d in ADS):
        return True, "ads"
    if mods.get("tracking") and any(match_suffix(name, d) for d in TRACKING):
        return True, "tracking"
    if mods.get("annoyances") and any(match_suffix(name, d) for d in ANNOY):
        return True, "annoyances"
    if not (mods.get("ads") or mods.get("tracking") or mods.get("annoyances")):
        return False, "off"
    return False, "ok"


def record(name, client, blocked):
    with _lock:
        st = _state["stats"]
        st["queries"] += 1
        if blocked:
            st["blocked"] += 1
            hosts = st["hosts"]
            hosts[name] = hosts.get(name, 0) + 1
            if len(hosts) > 800:
                smallest = sorted(hosts.items(), key=lambda kv: kv[1])[:200]
                for key, _ in smallest:
                    del hosts[key]
        recent = st["recent"]
        recent.append({"t": int(time.time()), "host": name,
                       "client": client, "blocked": blocked})
        del recent[:-100]


def decode_question(pkt):
    """Parst die Frage-Sektion. Gibt (qname, qtype, frage_ende) oder None."""
    if len(pkt) < 12:
        return None
    if struct.unpack(">H", pkt[4:6])[0] != 1:
        return None
    i = 12
    labels = []
    while True:
        if i >= len(pkt):
            return None
        length = pkt[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0:
            return None
        i += 1
        if i + length > len(pkt):
            return None
        try:
            labels.append(pkt[i:i + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        i += length
    if i + 4 > len(pkt):
        return None
    qtype = struct.unpack(">H", pkt[i:i + 2])[0]
    return (".".join(labels).lower(), qtype, i + 4)


def build_sinkhole(query, qend, qtype):
    header = query[:2] + struct.pack(">H", 0x8180) + struct.pack(">HHHH", 1, 1, 0, 0)
    question = query[12:qend]
    if qtype == 28:
        rdata = b"\x00" * 16
    else:
        rdata = b"\x00\x00\x00\x00"
    answer = (b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, TTL, len(rdata))
              + rdata)
    return header + question + answer


def build_servfail(query):
    try:
        dec = decode_question(query)
    except Exception:
        dec = None
    if dec:
        question = query[12:dec[2]]
        qdcount = 1
    else:
        question = b""
        qdcount = 0
    header = (query[:2] + struct.pack(">H", 0x8182)
              + struct.pack(">HHHH", qdcount, 0, 0, 0))
    return header + question


def build_nxdomain(query):
    """Lokale Namen schnell mit NXDOMAIN beantworten, damit Clients auf
    mDNS/LLMNR zurückfallen statt 2 s auf öffentliche Upstreams zu warten."""
    try:
        dec = decode_question(query)
    except Exception:
        dec = None
    if dec:
        question = query[12:dec[2]]
        qdcount = 1
    else:
        question = b""
        qdcount = 0
    header = (query[:2] + struct.pack(">H", 0x8183)
              + struct.pack(">HHHH", qdcount, 0, 0, 0))
    return header + question


def forward_to(query, servers):
    for ip in servers:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(query, (ip, 53))
            resp, _ = sock.recvfrom(4096)
            return resp
        except OSError:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return None


def forward(query):
    return forward_to(query, UPSTREAMS)


def handle_packet(query, client):
    dec = decode_question(query)
    if dec is None:
        resp = forward(query)
        return resp if resp else build_servfail(query)
    name, qtype, qend = dec
    blocked, reason = decide(name)
    if reason == "lan":
        # Lokale Namen gehören nicht an öffentliche Upstreams: wenn eine
        # Router-IP konfiguriert ist, dort fragen (löst z. B. fritz.box auf),
        # sonst schnell NXDOMAIN (Client fällt auf mDNS zurück).
        record(name, client, False)
        if ROUTER_IP:
            resp = forward_to(query, [ROUTER_IP])
            return resp if resp else build_nxdomain(query)
        return build_nxdomain(query)
    if qtype in (1, 28):
        record(name, client, blocked)
        if blocked:
            return build_sinkhole(query, qend, qtype)
    else:
        record(name, client, False)
    resp = forward(query)
    return resp if resp else build_servfail(query)


def dns_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", DNS_PORT))
    print("DNS UDP lauscht auf Port %d (Upstreams: %s)"
          % (DNS_PORT, ",".join(UPSTREAMS)), flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError as exc:
            print("UDP-Fehler: %s" % exc, flush=True)
            continue
        try:
            resp = handle_packet(data, addr[0])
        except Exception as exc:
            print("DNS-Fehler: %s" % exc, flush=True)
            try:
                resp = build_servfail(data)
            except Exception:
                continue
        if resp:
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass


def recvn(conn, count):
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_tcp_conn(conn, client):
    try:
        while True:
            prefix = recvn(conn, 2)
            if not prefix:
                return
            (length,) = struct.unpack(">H", prefix)
            if length < 12 or length > 4095:
                return
            query = recvn(conn, length)
            if not query:
                return
            try:
                resp = handle_packet(query, client)
            except Exception:
                resp = build_servfail(query)
            if resp:
                conn.sendall(struct.pack(">H", len(resp)) + resp)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def dns_tcp():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", DNS_PORT))
    srv.listen(32)
    print("DNS TCP lauscht auf Port %d" % DNS_PORT, flush=True)
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            continue
        thread = threading.Thread(target=handle_tcp_conn,
                                  args=(conn, addr[0]), daemon=True)
        thread.start()


def snapshot():
    with _lock:
        hosts = _state["stats"]["hosts"]
        top = sorted(hosts.items(), key=lambda kv: kv[1], reverse=True)[:15]
        return {
            "modules": dict(_state["modules"]),
            "custom": list(_state["custom"]),
            "allow": list(_state["allow"]),
            "listSizes": {"ads": len(ADS), "tracking": len(TRACKING),
                          "annoyances": len(ANNOY)},
            "stats": {
                "queries": _state["stats"]["queries"],
                "blocked": _state["stats"]["blocked"],
                "top": [{"host": h, "count": c} for h, c in top],
                "recent": list(reversed(_state["stats"]["recent"][-15:])),
            },
            "authRequired": bool(ADMIN_TOKEN),
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "TurtleBlock/1.0"

    def log_message(self, fmt, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return None

    def authorized(self):
        if not ADMIN_TOKEN:
            return True
        return self.headers.get("X-Auth-Token", "") == ADMIN_TOKEN

    def serve_index(self):
        try:
            with open(os.path.join(APP_DIR, "index.html"), "rb") as fh:
                body = fh.read()
        except OSError:
            body = ("<html><body><h1>TurtleBlock laeuft</h1>"
                    "<p>UI-Datei fehlt.</p></body></html>").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self.serve_index()
        if path == "/api/state":
            return self._json(snapshot())
        if path == "/api/test":
            host = parse_qs(urlparse(self.path).query).get("host", [""])[0]
            host = (host or "").strip().lower()
            blocked, reason = decide(host)
            return self._json({"host": host, "blocked": blocked,
                               "reason": reason})
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self.authorized():
            return self._json({"error": "Token fehlt oder falsch"}, 403)
        data = self._body()
        if data is None:
            return self._json({"error": "ungueltiges JSON"}, 400)
        path = urlparse(self.path).path
        if path == "/api/modules":
            mods = data.get("modules", {})
            if not isinstance(mods, dict):
                return self._json({"error": "modules erwartet"}, 400)
            with _lock:
                for key in ("ads", "tracking", "annoyances"):
                    if key in mods:
                        _state["modules"][key] = bool(mods[key])
            save_state()
            return self._json({"ok": True})
        if path == "/api/custom/add":
            value = str(data.get("filter", "")).strip().lower()
            if not value or len(value) > 120:
                return self._json({"error": "ungueltiger Filter"}, 400)
            with _lock:
                if value not in _state["custom"]:
                    _state["custom"] = ([value] + _state["custom"])[:500]
            save_state()
            return self._json({"ok": True})
        if path == "/api/custom/remove":
            value = str(data.get("filter", "")).strip().lower()
            with _lock:
                _state["custom"] = [x for x in _state["custom"] if x != value]
            save_state()
            return self._json({"ok": True})
        if path == "/api/allow/add":
            value = str(data.get("domain", "")).strip().lower().rstrip(".")
            if not value or len(value) > 120:
                return self._json({"error": "ungueltige Domain"}, 400)
            with _lock:
                if value not in _state["allow"]:
                    _state["allow"] = ([value] + _state["allow"])[:500]
            save_state()
            return self._json({"ok": True})
        if path == "/api/allow/remove":
            value = str(data.get("domain", "")).strip().lower()
            with _lock:
                _state["allow"] = [x for x in _state["allow"] if x != value]
            save_state()
            return self._json({"ok": True})
        if path == "/api/reset":
            with _lock:
                _state["stats"] = {"queries": 0, "blocked": 0,
                                   "hosts": {}, "recent": []}
            save_state()
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)


def saver():
    while True:
        time.sleep(60)
        save_state()


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    load_state()
    print("TurtleBlock Home: %d+%d+%d Domains geladen"
          % (len(ADS), len(TRACKING), len(ANNOY)), flush=True)

    def on_term(_signum, _frame):
        save_state()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    threading.Thread(target=dns_udp, daemon=True).start()
    threading.Thread(target=dns_tcp, daemon=True).start()
    threading.Thread(target=saver, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    print("Web-UI auf Port %d" % WEB_PORT, flush=True)
    try:
        server.serve_forever()
    finally:
        save_state()


if __name__ == "__main__":
    main()
