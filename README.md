# Policy-Web

Policy-Web ist eine browserbasierte Oberfläche zum Anzeigen und Verwalten von
Netzwerk-Policies. Verantwortungsbereiche, Benutzer, Netze, IP-Adressen,
FQDN-Ziele, Dienste und Regeln werden zentral gepflegt. Änderungen werden zunächst als Diff
erstellt und erst nach einer Bestätigung veröffentlicht.

Die Anwendung wird als fertiger Docker-Container bereitgestellt. Ein Download
des Quellcodes oder ein lokaler Build ist für den Betrieb nicht erforderlich.

## Inhalt

- [Funktionen](#funktionen)
- [Voraussetzungen](#voraussetzungen)
- [Schnellstart mit Docker Compose](#schnellstart-mit-docker-compose)
- [Ersteinrichtung](#ersteinrichtung)
- [Rollen und Berechtigungen](#rollen-und-berechtigungen)
- [Darstellung und Dark Mode](#darstellung-und-dark-mode)
- [Policies verwalten](#policies-verwalten)
- [Policies durchsuchen](#policies-durchsuchen)
- [SMTP konfigurieren](#smtp-konfigurieren)
- [Fortinet-Status konfigurieren](#fortinet-status-konfigurieren)
- [Updates und Rollback](#updates-und-rollback)
- [Backup](#backup)
- [TLS-Reverse-Proxy](#betrieb-hinter-einem-tls-reverse-proxy)
- [Fehlerdiagnose](#fehlerdiagnose)

## Funktionen

- Policies, Verantwortungsbereiche, Netze, IP-Adressen, FQDN-Ziele, Dienste und Regeln verwalten
- Lokale Anmeldung per E-Mail-Adresse und Kennwort ohne LDAP-Anbindung
- Rollen für Leser, Bearbeiter und Administratoren
- Hierarchische Verantwortungsbereiche mit lesendem Zugriff auf Unterbereiche
- Helle und dunkle Darstellung mit automatischer Systemerkennung
- Entwürfe, überprüfbare Diffs und unveränderliche Policy-Versionen
- Suche nach Dienstnamen, Beschreibungen, IP-Adressen, FQDNs, Netzobjekten und Ports
- Historische Policies und Diffs einsehen
- Optionaler Versand von Kennwort-Mails über SMTP
- Optionaler Fortinet-Status über einen authentifizierten JSON-Endpunkt
- Manuell pflegbares Changelog auf der Startseite

## Voraussetzungen

- Docker Engine 24 oder neuer
- Docker Compose v2 (`docker compose`)
- Derzeit eine `linux/amd64`-Umgebung
- Für den produktiven Betrieb: DNS-Name und TLS-Reverse-Proxy
- Optional: SMTP-Server für Kennwort-Mails

Das öffentliche Container-Image liegt in der GitHub Container Registry:

```text
ghcr.io/bartelluis/netspoc-web:latest
```

Verfügbare Images und Tags sind unter
[GitHub Packages](https://github.com/BartelLuis/Netspoc-Web/pkgs/container/netspoc-web)
aufgeführt. `latest` folgt dem aktuellen Stand des Standard-Branches. Für den
produktiven Betrieb sollte nach Möglichkeit ein Versions- oder `sha-...`-Tag
verwendet werden. Für diese Installation ist kein `docker compose build`
erforderlich.

## Schnellstart mit Docker Compose

Die folgenden Befehle sind für eine POSIX-Shell auf Linux formuliert. Unter
Windows sollten sie in WSL oder Git Bash ausgeführt werden; insbesondere die
binäre Backup-Weiterleitung ist nicht für Windows PowerShell 5.1 geeignet.

Die Anwendung wird während der Ersteinrichtung nur an `127.0.0.1` gebunden,
weil der initiale Administrator noch ohne Anmeldung angelegt werden muss.

### 1. Deployment-Verzeichnis vorbereiten

```sh
mkdir -p policy-web/data
cd policy-web
touch CHANGELOG.md
```

Der Container läuft als nicht privilegierter Benutzer mit UID `100` und GID
`101`. Auf einem Linux-Host muss das Datenverzeichnis für diesen Benutzer
schreibbar sein:

```sh
sudo chown -R 100:101 data
sudo chmod 750 data
```

Unter Docker Desktop für Windows oder macOS ist dieser `chown`-Schritt in der
Regel nicht erforderlich.

### 2. `compose.yaml` anlegen

```yaml
services:
  policyweb:
    image: ${POLICYWEB_IMAGE:-ghcr.io/bartelluis/netspoc-web:latest}
    restart: unless-stopped
    ports:
      - "${POLICYWEB_BIND:-127.0.0.1}:${POLICYWEB_PORT:-8080}:8080"
    environment:
      TZ: "${TZ:-Europe/Berlin}"
    env_file:
      - .env
    volumes:
      - ./policyweb.conf:/etc/policyweb/policyweb.conf:ro
      - ./CHANGELOG.md:/srv/policyweb/CHANGELOG.md:ro
      - ./data:/var/lib/policyweb/netspoc
      - policyweb-sessions:/var/lib/policyweb/sessions
      - policyweb-users:/var/lib/policyweb/users
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true

  create-user:
    image: ${POLICYWEB_IMAGE:-ghcr.io/bartelluis/netspoc-web:latest}
    profiles: ["tools"]
    entrypoint: ["/usr/local/bin/policyweb-create-user"]
    volumes:
      - policyweb-users:/var/lib/policyweb/users
    read_only: true
    security_opt:
      - no-new-privileges:true

volumes:
  policyweb-sessions:
  policyweb-users:
```

### 3. `policyweb.conf` anlegen

Diese Minimalkonfiguration startet ohne externes Netspoc-System und verwendet
die im Image enthaltenen Vorlagen:

```json
{
  "netspoc_data": "/var/lib/policyweb/netspoc",
  "user_dir": "/var/lib/policyweb/users",
  "session_dir": "/var/lib/policyweb/sessions",
  "noreply_address": "policyweb@example.net",
  "mail_transport": "sendmail",
  "mail_template": "/srv/policyweb/templates/mail",
  "html_template": "/srv/policyweb/templates/html",
  "fortinet_targets": []
}
```

`noreply_address` muss durch eine Adresse der eigenen Organisation ersetzt
werden. Der Sendmail-Modus ermöglicht zwar den Start, im Container ist jedoch
kein lokaler Mailserver installiert. Für Mailfunktionen muss später SMTP
konfiguriert werden.

### 4. `.env` anlegen

```dotenv
POLICYWEB_IMAGE=ghcr.io/bartelluis/netspoc-web:latest
POLICYWEB_BIND=127.0.0.1
POLICYWEB_PORT=8080
TZ=Europe/Berlin
```

Die Datei kann später auch SMTP- und Fortinet-Zugangsdaten enthalten und sollte
daher nur für den Administrator lesbar sein:

```sh
chmod 600 .env
chmod 644 policyweb.conf CHANGELOG.md
```

Die Konfiguration enthält keine Kennwörter; diese gehören ausschließlich in
`.env`. Der Lesemodus `644` ist erforderlich, damit der nicht privilegierte
Container die eingebundene Konfiguration lesen kann.

### 5. Eigenes Changelog anlegen

`CHANGELOG.md` kann jederzeit mit einem Texteditor gepflegt werden. Nach dem
Speichern genügt ein Neuladen der Startseite. Unterstützt werden Überschriften
der Ebenen 1 bis 3, Absätze und Aufzählungen mit `-` oder `*`.

```markdown
# Changelog

## 2026-08-19

- Policy-Web erstmals bereitgestellt
```

### 6. Container starten

```sh
docker compose pull
docker compose up -d
docker compose ps
```

Der Status wechselt nach dem Start auf `healthy`. Der Health-Endpunkt kann
zusätzlich geprüft werden:

```sh
curl --fail http://127.0.0.1:8080/backend/healthz
```

Die erwartete Antwort lautet:

```json
{"status":"ok"}
```

## Ersteinrichtung

Solange noch keine Policy vorhanden ist, ist die Initialadministration ohne
Login erreichbar. Die Anwendung darf in diesem Zustand nicht öffentlich ins
Internet gestellt werden. Es gibt kein voreingestelltes Benutzerkonto und kein
Standardkennwort.

Bei einer Installation auf einem entfernten Server kann ein SSH-Tunnel genutzt
werden:

```sh
ssh -L 8080:127.0.0.1:8080 user@policy-server.example.net
```

Anschließend im lokalen Browser öffnen:

```text
http://127.0.0.1:8080/admin.html
```

Für die erste Policy sind mindestens folgende Angaben erforderlich:

1. Einen Policy-Namen eintragen.
2. Einen Benutzer mit E-Mail-Adresse, Kennwort und Rolle `Administrator` anlegen.
3. Einen Verantwortungsbereich anlegen.
4. Die E-Mail-Adresse des Benutzers als Bereichsadministrator eintragen.
5. Optional bereits Netze, IP-Adressen, FQDN-Ziele, Dienste und Regeln anlegen.
6. Auf **Diff erstellen** klicken. Bei der Ersteinrichtung wird dadurch die erste
   Policy direkt veröffentlicht.

Danach erfolgt die Anmeldung unter `http://127.0.0.1:8080/` mit der angelegten
E-Mail-Adresse und dem Kennwort.

## Rollen und Berechtigungen

Policy-Rolle und Verantwortungsbereich sind voneinander getrennt. Eine
Policy-Rolle bestimmt, ob die Administration sichtbar ist. Die Zuordnung zu
Verantwortungsbereichen bestimmt, welche Netze und Dienste ein Benutzer sehen
kann.

| Rolle | Berechtigungen |
| --- | --- |
| Leser | Veröffentlichte Policies, Netze, Dienste und Diffs ansehen und durchsuchen |
| Bearbeiter | Zusätzlich Entwürfe ändern, speichern und neue Diffs erstellen |
| Administrator | Zusätzlich Diffs bestätigen und als neue Policy veröffentlichen |

Leser sehen den Menüpunkt **Administration** nicht. Ein übergeordneter
Verantwortungsbereich besitzt lesenden Zugriff auf seine untergeordneten
Bereiche.

## Darstellung und Dark Mode

Die Schaltfläche **Dark Mode** (im dunklen Modus **Light Mode**) wechselt die
Darstellung. Die Auswahl gilt auch für Anmeldung, Administration, Changelog und
Kennwortseiten und bleibt im verwendeten Browser gespeichert. Solange noch
keine Auswahl getroffen wurde, folgt Policy-Web automatisch der Hell-/Dunkel-
Einstellung des Betriebssystems.

## Policies verwalten

Administratoren und Bearbeiter öffnen nach der Anmeldung den Menüpunkt
**Administration**.

### Benutzer

- Die E-Mail-Adresse ist gleichzeitig der Anmeldename.
- Das Kennwort ist bei neuen Benutzern erforderlich.
- Ein leeres Kennwortfeld lässt ein bestehendes Kennwort unverändert.
- Nicht jeder Benutzer sollte Administrator sein.

### Verantwortungsbereiche

- Benutzer, Bereichsadministratoren und Beobachter werden als kommagetrennte
  E-Mail-Adressen eingetragen.
- Ein Verantwortungsbereich kann einen übergeordneten Bereich besitzen.
- Ein Verantwortungsbereich kann als Sammelbereich konfiguriert werden. Mit
  **Alle VBs lesen** zeigt er die Daten sämtlicher Verantwortungsbereiche in
  einer gemeinsamen Ansicht. Über **Zusätzlicher Lesezugriff auf** lassen sich
  alternativ bestimmte Bereiche auswählen; deren Unterbereiche werden
  automatisch einbezogen.
- Der Sammelbereich bleibt in der normalen Auswahl sichtbar. Wird er
  ausgewählt, werden Netze, enthaltene IP-Adressen, Dienste und Regeln aus den
  konfigurierten Bereichen zusammengeführt.
- Netze und einzelne IP-Adressen können unterschiedlichen Bereichen gehören.
- Beobachter werden als Metadaten geführt und erhalten dadurch keine
  Zugriffsrechte. Der Container versendet derzeit nicht automatisch an
  Beobachter.

### Netze und IP-Adressen

- Netze werden als CIDR eingetragen, zum Beispiel `172.25.26.0/24`.
- IP-Adressen werden als enthaltene Ressourcen des Netzes angelegt.
- Der Name einer IP-Adresse ist optional. Ohne Namen wird beispielsweise aus
  `172.25.26.1` automatisch `ip-172-25-26-1`.
- Eine IP-Adresse muss innerhalb des zugehörigen Netzes liegen. Der daraus
  erzeugte oder manuell gesetzte Ressourcenname muss eindeutig sein.

### FQDN-Ziele

- FQDNs werden als eigenständige Zielobjekte angelegt, zum Beispiel mit dem
  Objektnamen `customer-api` und dem DNS-Namen `api.example.org`.
- Jedes FQDN-Ziel gehört zu einem Verantwortungsbereich.
- In Regeln wird es als `fqdn:customer-api` referenziert. FQDN-Objekte sind nur
  als Ziel zulässig und werden nicht durch Policy-Web in IP-Adressen aufgelöst.

### Dienste und Regeln

- Dienste können einem oder mehreren Verantwortungsbereichen gehören.
- Quellen und Ziele referenzieren vollständige Objektnamen wie
  `network:clients`, `host:webserver` oder als Ziel `fqdn:customer-api`.
- Über **Benutzerseite** wird pro Regel festgelegt, ob die Benutzerobjekte des
  Dienstes aus der Quelle, dem Ziel, beiden Seiten oder gar nicht abgeleitet
  werden. Diese Objekte erscheinen anschließend unter **Benutzer (User) des
  Dienstes** und der Dienst unter **Genutzte**.
- Mehrere Quellen, Ziele oder Protokolle werden mit Komma getrennt.
- Protokolle werden zum Beispiel als `tcp 443`, `udp 53` oder `icmp` angegeben.

### Entwurf, Diff und Veröffentlichung

1. **Entwurf speichern** speichert den aktuellen Arbeitsstand, ändert aber nicht
   die aktive Policy.
2. **Diff erstellen** validiert alle Referenzen und legt eine neue, eindeutige
   Policy-ID an.
3. Ein Administrator prüft den Diff und bestätigt ihn.
4. Erst die Bestätigung veröffentlicht genau diese Revision.

Ändert sich die zugrunde liegende Policy zwischen Erstellung und Bestätigung,
muss der Diff neu erstellt werden. Frühere und noch ausstehende Revisionen sind
in der Diff- und Policy-Historie einsehbar.

## Policies durchsuchen

Im Bereich **Dienste** öffnet die Schaltfläche **Suche** zwei Sucharten:

- **Dienstsuche:** Dienstname und optional Beschreibung
- **Netz-/IP-/FQDN-Suche:** IP-Adresse, FQDN, Netzobjekt, zwei Endpunkte oder Protokoll/Port

Übergeordnete und enthaltene Netze können in die Suche einbezogen werden. Die
Suche berücksichtigt sowohl direkte Quellen und Ziele als auch Dienste mit
separaten Benutzern.

## SMTP konfigurieren

Mail wird ausschließlich über `policyweb.conf` und `.env` konfiguriert, nicht
über die Weboberfläche. Für einen SMTP-Server mit Anmeldung werden die
Mail-Einträge in `policyweb.conf` wie folgt ersetzt beziehungsweise ergänzt:

```json
{
  "noreply_address": "policyweb@example.net",
  "mail_transport": "smtp",
  "smtp_host": "smtp.example.net",
  "smtp_port": 587,
  "smtp_username_env": "POLICYWEB_SMTP_USERNAME",
  "smtp_password_env": "POLICYWEB_SMTP_PASSWORD"
}
```

Die übrigen Konfigurationswerte aus der Minimalkonfiguration bleiben erhalten.
Die Zugangsdaten kommen in `.env`:

```dotenv
POLICYWEB_SMTP_USERNAME=policyweb
POLICYWEB_SMTP_PASSWORD=ein-sicheres-kennwort
```

Danach den Container neu erstellen:

```sh
docker compose up -d --force-recreate policyweb
docker compose logs --tail=50 policyweb
```

Für einen internen SMTP-Relay ohne Anmeldung werden
`smtp_username_env` und `smtp_password_env` vollständig aus der JSON-Datei
entfernt. Der Client verwendet STARTTLS, wenn der Server es anbietet. Für
produktive Installationen sollte ein vertrauenswürdiger SMTP-Relay verwendet
werden, der TLS verlangt.

## Fortinet-Status konfigurieren

Optional kann Policy-Web die Erreichbarkeit und Versionsinformationen von
FortiGate oder FortiManager abfragen. Die Zugangsdaten werden nur über
Umgebungsvariablen referenziert. Es gibt dafür derzeit keine eigene
Geräteansicht in der GUI.

Beispiel für den Eintrag `fortinet_targets` in der bestehenden
`policyweb.conf`:

```json
{
  "fortinet_targets": [
    {
      "name": "edge-1",
      "type": "fortigate",
      "url": "https://edge-1.example.net",
      "vdom": "root",
      "token_env": "EDGE_1_API_TOKEN"
    },
    {
      "name": "manager-1",
      "type": "fortimanager",
      "url": "https://fmg.example.net",
      "adom": "production",
      "username_env": "FMG_API_USER",
      "password_env": "FMG_API_PASSWORD"
    }
  ]
}
```

Passende Einträge in `.env`:

```dotenv
EDGE_1_API_TOKEN=fortigate-api-token
FMG_API_USER=api-user
FMG_API_PASSWORD=api-kennwort
```

Die Ziel-URL muss HTTPS verwenden. Für eine interne Zertifizierungsstelle kann
eine PEM-Datei read-only in den Container gemountet und über `ca_file`
referenziert werden. `insecure_skip_verify` sollte nicht in Produktion
verwendet werden. Die Integration zeigt den Status an; sie installiert keine
Policy auf dem Gerät.

Nach einer Änderung von `policyweb.conf` oder `.env` muss der Container neu
erstellt werden:

```sh
docker compose up -d --force-recreate policyweb
```

Ein angemeldeter Benutzer kann den Status anschließend als JSON unter folgendem
Endpunkt abrufen:

```text
/backend/fortinet/status
```

## Kennwort per Kommandozeile zurücksetzen

Falls ein Benutzer nicht mehr über die Weboberfläche verwaltet werden kann,
kann sein lokales Kennwort mit dem Hilfscontainer angelegt oder zurückgesetzt
werden:

```sh
read -r -s -p 'Neues Kennwort: ' POLICYWEB_PASSWORD; echo
printf '%s' "$POLICYWEB_PASSWORD" | docker compose run --rm -T create-user \
  --email admin@example.net --password-stdin
unset POLICYWEB_PASSWORD
```

Der Befehl muss im gleichen Deployment-Verzeichnis ausgeführt werden. Andernfalls
kann Docker Compose ein anderes Benutzer-Volume verwenden.

## Updates und Rollback

Vor jedem Update sollte ein Backup angelegt werden.

1. In `.env` das gewünschte Image setzen. `latest` lädt die aktuelle Version;
   für einen reproduzierbaren Betrieb wird `latest` durch einen tatsächlich
   unter GitHub Packages veröffentlichten Versions- oder `sha-...`-Tag ersetzt:

   ```dotenv
   POLICYWEB_IMAGE=ghcr.io/bartelluis/netspoc-web:latest
   ```

2. Image laden und Container neu erstellen:

   ```sh
   docker compose pull policyweb create-user
   docker compose up -d --force-recreate policyweb
   docker compose ps
   docker compose logs --tail=50 policyweb
   ```

3. Health-Endpunkt und Anmeldung prüfen.

Für einen Rollback wird der vorherige Tag oder ein vollständiger Digest in
`POLICYWEB_IMAGE` eingetragen und derselbe Ablauf wiederholt. Datenmigrationen
sollten nur zusammen mit einem passenden Backup zurückgerollt werden.

## Backup

Zu sichern sind:

- das komplette Verzeichnis `data` mit SQLite-Datenbank und allen Policy-Versionen
- das Docker-Volume `policyweb-users` mit lokalen Anmeldedaten
- `compose.yaml`, `policyweb.conf`, `.env` und `CHANGELOG.md`

Aktive Sitzungen müssen normalerweise nicht gesichert werden. Ohne
Session-Volume müssen sich lediglich alle Benutzer neu anmelden.

Für ein konsistentes Backup wird der Webcontainer kurz gestoppt:

```sh
umask 077
install -d -m 700 backups
docker compose stop policyweb

tar -czf backups/policyweb-config.tar.gz \
  compose.yaml policyweb.conf .env CHANGELOG.md

docker compose run --rm --no-deps -T --entrypoint sh policyweb \
  -c 'tar -C /var/lib/policyweb -czf - netspoc users' \
  > backups/policyweb-state.tar.gz

docker compose start policyweb
```

Backups enthalten Kennworthashes und möglicherweise Zugangsdaten und müssen
entsprechend geschützt werden. Zum Wiederherstellen sollte eine saubere
Deployment-Instanz verwendet, der Container gestoppt und anschließend sowohl
das Datenverzeichnis als auch das Benutzer-Volume aus demselben Backup-Stand
wiederhergestellt werden.

`docker compose down` behält benannte Volumes. Der Befehl
`docker compose down -v` löscht dagegen Benutzerkonten und Sitzungen und darf
nicht für ein normales Update verwendet werden.

## Betrieb hinter einem TLS-Reverse-Proxy

Der Container selbst stellt HTTP auf Port `8080` bereit. Für den produktiven
Betrieb sollte er weiterhin nur an `127.0.0.1` gebunden und über einen
TLS-Reverse-Proxy veröffentlicht werden.

Minimales Caddy-Beispiel:

```caddyfile
policy.example.net {
  header Strict-Transport-Security "max-age=31536000"
  reverse_proxy 127.0.0.1:8080
}
```

Policy-Web sollte unter der Wurzel eines eigenen Hosts betrieben werden, nicht
unter einem zusätzlichen URL-Unterpfad. Der HTTP-Port des Containers darf nicht
öffentlich angeboten werden. Nach erfolgreicher Ersteinrichtung kann der
Reverse-Proxy freigeschaltet werden; Clients sollten ausschließlich die
HTTPS-Adresse verwenden. Der HSTS-Header verhindert nach dem ersten sicheren
Aufruf weitere unverschlüsselte Zugriffe auf diesen Host.

## Fehlerdiagnose

### Container startet nicht oder ist `unhealthy`

```sh
docker compose ps
docker compose logs --tail=100 policyweb
docker compose config
```

Häufige Ursachen sind ungültiges JSON in `policyweb.conf`, unbekannte
Konfigurationsschlüssel, fehlende SMTP-Umgebungsvariablen oder nicht beschreibbare
Policy-Daten.

### `permission denied` bei SQLite oder Veröffentlichung

Auf Linux die Besitzrechte des Datenverzeichnisses prüfen:

```sh
sudo chown -R 100:101 data
sudo chmod 750 data
docker compose restart policyweb
```

### Administration wird nicht angezeigt

Die Administration ist nur für Benutzer mit der Policy-Rolle `Bearbeiter` oder
`Administrator` sichtbar. Leser sehen ausschließlich die normalen Ansichten.

### Sitzung ist abgelaufen

Zur Startseite wechseln und erneut anmelden. Erscheint die Meldung unmittelbar
nach einer korrekten Anmeldung, muss die E-Mail-Adresse in der veröffentlichten
Policy einem Verantwortungsbereich als Benutzer oder Bereichsadministrator
zugeordnet sein. Ein Verlust des Session-Volumes meldet alle Benutzer ab,
beschädigt aber keine Policy-Daten.

### Netze, IP-Adressen oder Dienste fehlen

Prüfen, ob die Änderung als Diff bestätigt und veröffentlicht wurde, ob der
richtige Verantwortungsbereich ausgewählt ist und ob die Ressource diesem oder
einem untergeordneten Bereich gehört.

### Ein Diff kann nicht bestätigt werden

Wurde seit der Diff-Erstellung bereits eine andere Policy veröffentlicht, ist
die Basisrevision veraltet. Den Entwurf erneut prüfen und einen neuen Diff
erstellen.

### Mails werden nicht versendet

- `mail_transport` muss auf `smtp` stehen.
- Host, Port und Absenderadresse müssen stimmen.
- Bei Authentifizierung müssen beide referenzierten Variablen in `.env` gesetzt sein.
- Nach Änderungen muss der Container neu erstellt werden.
- Details stehen in `docker compose logs policyweb`.

### GHCR-Image kann nicht geladen werden

Das Image ist öffentlich und benötigt normalerweise keine Anmeldung. Falls das
Package später privat betrieben wird, ist eine Anmeldung mit einem GitHub-Token
mit Berechtigung `read:packages` erforderlich:

```sh
echo "$GHCR_TOKEN" | docker login ghcr.io -u GITHUB_USER --password-stdin
docker compose pull
```

## Sicherheitshinweise

- Die Ersteinrichtung niemals ungeschützt öffentlich erreichbar machen.
- Im produktiven Betrieb ausschließlich TLS mit HSTS verwenden und Port `8080`
  nur an `127.0.0.1` binden.
- `.env`, Konfiguration und Backups nicht in ein öffentliches Repository legen.
- Nur benötigte Fortinet-Rechte an API-Benutzer oder Token vergeben.
- Regelmäßig Backups und Updates testen.
- Niemals versehentlich `docker compose down -v` ausführen.

Der Container läuft standardmäßig ohne Root-Rechte, mit read-only Root-Dateisystem
und `no-new-privileges`.

## Support und Lizenz

Fehler und Verbesserungsvorschläge können im
[GitHub-Issue-Tracker](https://github.com/BartelLuis/Netspoc-Web/issues)
gemeldet werden. Dabei keine Kennwörter, Tokens, vollständigen Policies oder
andere vertrauliche Daten veröffentlichen.

Policy-Web steht unter der GNU General Public License Version 3. Details stehen
in [LICENSE](LICENSE).
