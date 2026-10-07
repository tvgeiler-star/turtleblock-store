# Blocklisten — Herkunft & Format

Alle drei Listen stammen aus der **Adblocker-Pro-Browser-Extension v2.10.0**
(`adblocker-extension/rules/*.json`), genauer aus den `requestDomains`-Feldern:

| Datei | Extension-Quellen | Modul |
|---|---|---|
| `ads.txt` | `turtlecute.json` (TurtleCute-Hosts), `superlist.json` (Ads/Video/Miner), `easylist.json`, `url-patterns.json` | Werbung |
| `tracking.txt` | `easyprivacy.json`, `turtlecute` Analytics-Hosts, `superlist` Analytics/Fingerprinting, `surrogates.json`-Hosts | Tracking & Analytics |
| `annoyances.txt` | `annoyances.json`, `turtlecute` Social/OEM-Hosts, `superlist` Social/Consent/OEM/Affiliate | Social, Consent & Hersteller |

**Format:** eine Domain pro Zeile, `#` = Kommentar. Subdomains werden vom
Server automatisch mit blockiert (Suffix-Match, wie AdGuard `||domain^`).

**Wiederverwendung:** Die Dateien sind direkt als AdGuard-Home-/uBlock-Listen
nutzbar — pro Zeile vorne `||` und hinten `^` ergänzen.

**Bewusste Abweichungen zum Browser (DNS kann weniger — und muss vorsichtiger sein):**
- URL-Muster (`/pagead.js`, `/ads/`, Regexe) wirken nur im Browser und sind
  hier nicht enthalten — reine Pfad-Regeln kann DNS nicht sehen.
- `cleanurl.json` (utm_/gclid/fbclid-Stripping) braucht HTTP-Sichtbarkeit;
  dafür sind hier zusätzlich reine Tracking-Pixel-Hosts enthalten.
- Surrogate (`noop.js`-Redirects) werden als sanftes Sinkhole (`0.0.0.0`)
  statt NXDOMAIN beantwortet — gleiche Idee, kein harter Abbruch.
- Reine Video-/Player-CDNs (`*.googlevideo.com`, `jwpcdn`, `jwpltx`) und
  bare Content-Domains (`facebook.com`, `vk.com`, `yandex.ru`) sind
  ausgenommen, damit YouTube & Co. nicht brechen. Wer mehr will: eigene Filter.
- LAN-Schutz (`lan-allow.json`) steckt direkt im Server: `.local`, `.lan`,
  `umbrel`, `fritz.box`, Reverse-DNS und einteilige Hostnamen werden nie
  blockiert — wichtig, damit Umbrel/Router/NAS erreichbar bleiben.
