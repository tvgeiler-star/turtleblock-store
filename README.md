# TurtleBlock App Store (für Umbrel)

Community App Store mit **TurtleBlock Home** — netzwerkweiter Ad- & Tracker-
Blocker mit der Filter-DNA der Adblocker-Pro-Browser-Extension
(`../adblocker-extension`). Wie AdGuard Home, aber mit deinen Listen:
installierbar und deinstallierbar direkt über die Umbrel-Oberfläche.

## Struktur

```
turtleblock-store/
  umbrel-app-store.yml                 # Store-ID "turtleblock"
  turtleblock-home/
    umbrel-app.yml                     # App-Manifest (id, port 8196, ...)
    docker-compose.yml                 # python:3.12-slim, Host-Netzwerk (DNS 53 + UI 8196)
    icon.svg
    data/.gitkeep
    app/
      server.py                        # DNS (UDP+TCP) + Web-UI/API, nur Stdlib
      index.html                       # deutsche UI im Popup-Stil
      lists/ads.txt                    # 199 Werbe-Domains
      lists/tracking.txt               # 181 Tracker/Analytics-Domains
      lists/annoyances.txt             # 178 Social/Consent/OEM-Domains
      lists/README.txt                 # Herkunft & Format der Listen
```

## Installieren (Umbrel)

1. Diesen Ordner als Git-Repo pushen (z. B. `turtleblock-store` auf GitHub).
2. In umbrelOS: **App Store → … → Community App Store hinzufügen** und die
   Repo-URL eintragen.
3. **TurtleBlock Home → Installieren.** Danach nur ein DNS-Filter gleichzeitig
   laufen lassen (AdGuard/Pi-hole ggf. zuerst deinstallieren — beide wollen
   Port 53).
4. Im Router (FritzBox: Heimnetz → Netzwerk → IPv4) die **Umbrel-IP als
   DNS-Server** eintragen (ggf. auch IPv6 bzw. pro Gerät).
5. App öffnen (Port **8196**), im Testfeld `doubleclick.net` prüfen → muss
   **blockiert** melden. Fertig.

## Deinstallieren

In umbrelOS **TurtleBlock Home → Deinstallieren**. Dabei wird der Container
entfernt; Reste unter `…/app-data/turtleblock-home` (Statistiken, eigene
Filter) löscht umbrelOS mit. Danach im Router wieder den alten DNS-Server
eintragen (sonst kein Internet!).

## Update

`version` in `turtleblock-home/umbrel-app.yml` erhöhen (z. B. `"1.0.1"`) und
`releaseNotes` ergänzen — umbrelOS bietet das Update dann automatisch an.

## Hinweise für die Veröffentlichung

- `umbrel-app.yml`: `repo:`/`support:`-URLs auf dein GitHub-Repo zeigen lassen
  (stehen aktuell als Kommentar drin).
- Für den **offiziellen** Store: Docker-Image per sha256-Digest pinnen
  (`python:3.12-slim@sha256:…`, Multi-Arch-Digest von Docker Hub), Icon
  256×256 ohne runde Ecken (liegt bei) und 3–5 Screenshots 1440×900 beilegen,
  danach PR an `getumbrel/umbrel-apps`.
- Optionaler Schreibschutz der UI: In `docker-compose.yml`
  `ADMIN_TOKEN: ${APP_PASSWORD:-}` ist vorbereitet — sobald gesetzt, verlangen
  alle speichernden API-Aufrufe den Header `X-Auth-Token`.

## Was DNS kann — und was nicht (ehrlich)

| Extension (Browser) | TurtleBlock (DNS) |
|---|---|
| DNR-Netzwerkfilter (Domains) | ✅ voll übernommen (~450 Domains, 3 Module) |
| URL-Pfade (`/pagead.js`, Regexe) | ❌ DNS sieht nur Domains |
| Cosmetic-Hiding, Scriptlets, Anti-Adblock | ❌ braucht weiter die Extension |
| Tracking-Parameter strippen (utm_, gclid …) | ❌ dafür Tracking-Pixel-Hosts extra |
| LAN-Ausnahmen, eigene Filter, Stats, Top-Hosts | ✅ übernommen (Allowlist, Testfeld, Zähler) |

Faustregel aus der Extension-Doku: DNS allein schafft ca. 40–60 %, zusammen mit
der Extension bis ~100 % (TurtleCute-Test). Beide ergänzen sich.
