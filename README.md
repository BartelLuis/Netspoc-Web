# Policy-Web

Policy-Web ist eine browserbasierte Oberfläche zum Anzeigen und Verwalten von
Netzwerk-Policies. Verantwortungsbereiche, Benutzer, Netze, IP-Adressen,
FQDN-Ziele, Dienste und Regeln werden zentral gepflegt. Änderungen durchlaufen
verbindlich Staging, Vier-Augen-Freigabe, Veröffentlichung und – sofern
konfiguriert – ein verifiziertes FortiGate-Deployment.

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
- [Antragswesen](#antragswesen)
- [Policies durchsuchen](#policies-durchsuchen)
- [Geräte und Routing analysieren](#geräte-und-routing-analysieren)
- [SMTP konfigurieren](#smtp-konfigurieren)
- [Fortinet-Staging und Deployment konfigurieren](#fortinet-staging-und-deployment-konfigurieren)
- [Updates und Rollback](#updates-und-rollback)
- [Backup](#backup)
- [TLS-Reverse-Proxy](#betrieb-hinter-einem-tls-reverse-proxy)
- [Fehlerdiagnose](#fehlerdiagnose)

## Funktionen

- Policies, Verantwortungsbereiche, Netze, IP-Adressen, FQDN-Ziele, Dienste und Regeln verwalten
- Lokale Anmeldung sowie optionale LDAP-Anmeldung mit manuellem Benutzer-Sync
- Getrennte Rollen für Leser, Bearbeiter, Reviewer, Deployer, Administratoren und Developer
- Hierarchische Verantwortungsbereiche mit lesendem Zugriff auf Unterbereiche
- Helle und dunkle Darstellung mit automatischer Systemerkennung
- Entwürfe, Staging mit Risiko- und Command-Vorschau, Vier-Augen-Freigabe und unveränderliche Policy-Versionen
- Händisch vergebene, validierte FortiGate-Policy-Namen
- Regeln zwischen Diensten kopieren oder verschieben
- Geplanter Wartungsmodus mit Admin-/Developer-Zugang und Hinweis auf der Startseite
- Suche nach Dienstnamen, Beschreibungen, IP-Adressen, FQDNs, Netzobjekten und Ports
- Web-Verwaltung von FortiGates und Read-only-Auswertung ihrer Routingtabellen für Quell- und Zielnetze
- Revisionssichere Anträge für Regeländerungen und neue Dienste mit Vier-Augen-Freigabe
- Historische Policies und Diffs einsehen
- Optionaler Versand von Kennwort-Mails über SMTP
- FortiOS-7.4.x-Preflight, Deployment-Verifikation, automatischer Fehler-Rollback und Drift-Prüfung
- Audit-Protokoll, Where-used-Prüfung und Rollback historischer Revisionen
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

Die Anwendung wird während der Ersteinrichtung nur an `127.0.0.1` gebunden.
Der erste Administrator wird über einen eigenen, token-geschützten Setup-Dialog
angelegt; die eigentliche Administrationsoberfläche ist auch in dieser Phase
nicht anonym erreichbar.

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
  "public_base_url": "http://127.0.0.1:8080",
  "fortinet_targets": [],
  "maintenance_mode": false,
  "maintenance_message": ""
}
```

`noreply_address` muss durch eine Adresse der eigenen Organisation ersetzt
werden. Der Sendmail-Modus ermöglicht zwar den Start, im Container ist jedoch
kein lokaler Mailserver installiert. Für Mailfunktionen muss später SMTP
konfiguriert werden.

`public_base_url` ist der feste, extern sichtbare Ursprung für Links in
Kennwort-Bestätigungsmails. Er muss exakt dem Ursprung entsprechen, unter dem
der Browser Policy-Web aufruft, damit der Sitzungscookie bei der Bestätigung
verwendet wird. Produktiv ist eine HTTPS-URL wie
`https://policy.example.org` einzutragen; unverschlüsseltes HTTP wird nur für
`localhost` und Loopback-Adressen akzeptiert. Fehlt der Wert, bleibt die
Kennwortanforderung deaktiviert. Der Link zeigt zunächst eine Bestätigungsseite;
erst deren explizites Absenden per POST ändert das Kennwort.

`maintenance_mode` und `maintenance_message` sind die Startwerte. Danach kann
ein Administrator den Wartungsmodus im Admin-Panel sofort aktivieren,
deaktivieren oder mit Start und Ende planen; dafür ist kein Neustart nötig. Auf
der Start- und Anmeldeseite erscheint die hinterlegte Nachricht. Während eines
aktiven Wartungsfensters können sich ausschließlich Administratoren anmelden;
bereits angemeldete Nicht-Administratoren werden beim nächsten Request
abgemeldet.

### LDAP-Anmeldung und manueller Benutzersync

LDAP wird über `policyweb.conf` aktiviert. Beispiel für Active Directory:

```json
{
  "ldap_uri": "ldaps://ad.example.org:636",
  "ldap_dn_template": "EXAMPLE\\%s",
  "ldap_base_dn": "DC=example,DC=org",
  "ldap_filter_template": "sAMAccountName=%s",
  "ldap_sync_filter": "(&(objectClass=user)(mail=*))",
  "ldap_user_attr": "sAMAccountName",
  "ldap_email_attr": "mail",
  "ldap_id_attr": "objectGUID",
  "ldap_bind_dn_env": "POLICYWEB_LDAP_BIND_DN",
  "ldap_bind_password_env": "POLICYWEB_LDAP_BIND_PASSWORD"
}
```

Die Zugangsdaten des ausschließlich lesenden Sync-Kontos werden über die
referenzierten Umgebungsvariablen bereitgestellt. Administratoren starten den
Import über „LDAP synchronisieren“ in der Benutzerverwaltung. Zuerst wird eine
zeitlich begrenzte, benutzergebundene Vorschau angezeigt; erst die Bestätigung
übernimmt exakt diesen geprüften Stand in den Entwurf. Neu gefundene Konten
erhalten zunächst die Rolle `viewer`; Rolle und effektive E-Mail-Adresse können
anschließend lokal geändert werden. LDAP-ID, Benutzername, Herkunft und
Aktivstatus sind nicht editierbar. Nicht mehr im Verzeichnis gefundene Konten
werden deaktiviert, nicht gelöscht. LDAP ist ausschließlich über `ldaps://`
zulässig. Ein LDAP-Benutzer kann sich erst anmelden, nachdem der synchronisierte
Entwurf veröffentlicht wurde.

### 4. `.env` anlegen

```dotenv
POLICYWEB_IMAGE=ghcr.io/bartelluis/netspoc-web:latest
POLICYWEB_BIND=127.0.0.1
POLICYWEB_PORT=8080
TZ=Europe/Berlin
POLICYWEB_BOOTSTRAP_TOKEN=ein-langes-zufälliges-einmalgeheimnis
POLICYWEB_COOKIE_SECURE=false
POLICYWEB_TRUST_PROXY_HEADERS=false
POLICYWEB_FORTIGATE_READ_ONLY=true
```

`POLICYWEB_BOOTSTRAP_TOKEN` wird nur für die einmalige Ersteinrichtung benötigt
und auf der Anmeldeseite einmalig eingegeben. Danach sollte die Variable aus
`.env` entfernt und der Container neu erstellt werden. Die beiden `false`-Werte
sind ausschließlich für die lokale HTTP-Ersteinrichtung gedacht; die
Produktivwerte hinter einem vertrauenswürdigen TLS-Reverse-Proxy stehen im
Abschnitt [Betrieb hinter einem TLS-Reverse-Proxy](#betrieb-hinter-einem-tls-reverse-proxy).

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

Solange noch keine Policy vorhanden ist, zeigt die normale Anmeldeseite
automatisch den Dialog **Sichere Ersteinrichtung**. Es gibt kein voreingestelltes
Benutzerkonto und kein Standardkennwort. Der einmalige Vorgang verlangt das
serverseitige `POLICYWEB_BOOTSTRAP_TOKEN`, legt einen lokalen Administrator mit
Argon2id-Kennworthash sowie eine minimale Ausgangspolicy an und meldet diesen
Administrator direkt in einer neuen Session an. Danach ist der Setup-Endpunkt
dauerhaft gesperrt.

Bei einer Installation auf einem entfernten Server kann ein SSH-Tunnel genutzt
werden:

```sh
ssh -L 8080:127.0.0.1:8080 user@policy-server.example.net
```

Anschließend im lokalen Browser öffnen:

```text
http://127.0.0.1:8080/
```

Im Dialog werden nur vier Angaben benötigt:

1. das einmalige Bootstrap-Token aus `.env`,
2. die E-Mail-Adresse des ersten Administrators,
3. ein selbst gewähltes Kennwort mit mindestens zwölf Zeichen und
4. die Kennwortbestätigung.

Nach dem erfolgreichen Wechsel in die Anwendung muss das Bootstrap-Token aus
`.env` entfernt und der Container neu erstellt werden. Ein paralleler oder
wiederholter Setup-Versuch kann die veröffentlichte Ausgangspolicy nicht
überschreiben. `app.html`, `admin.html` und `devices.html` werden serverseitig
durch dieselbe Session- und Rollenprüfung wie die APIs geschützt.

Kennwörter bleiben weiterhin außerhalb von Policy, Entwurf und Revision. Das
`create-user`-Werkzeug dient nur noch zum Anlegen weiterer lokaler Konten oder
zur kontrollierten Wiederherstellung eines Zugangs.

## Rollen und Berechtigungen

Policy-Rolle und Verantwortungsbereich sind voneinander getrennt. Eine
Policy-Rolle bestimmt, ob die Administration sichtbar ist. Die Zuordnung zu
Verantwortungsbereichen bestimmt, welche Netze und Dienste ein Benutzer sehen
kann. Die Staging-Superrolle `developer` ist die ausdrückliche Ausnahme und
besitzt Zugriff auf alle Verantwortungsbereiche.

| Rolle | Berechtigungen |
| --- | --- |
| Leser (`viewer`) | Veröffentlichte Policies, Netze und Dienste ansehen, durchsuchen und Änderungen beantragen |
| Bearbeiter (`editor`) | Fachliche Entwürfe ändern, speichern und Anträge oder Entwürfe in das Staging geben; keine Benutzer- oder Rechteverwaltung |
| Reviewer (`reviewer`) | Anträge, Staging, Risiken und Commands prüfen sowie fremde Revisionen freigeben oder ablehnen |
| Deployer (`deployer`) | Veröffentlichte Revisionen ausrollen und Drift prüfen |
| Administrator (`admin`) | Benutzer, LDAP-Sync, Wartungsmodus, Rollback und alle fachlichen Funktionen verwalten |
| Developer (`developer`) | Alle Admin-, Editor-, Reviewer- und Deployer-Funktionen in allen Verantwortungsbereichen; darf eigene Revisionen und Anträge selbst freigeben oder ablehnen |

Auch Administratoren dürfen eine selbst erstellte Revision nicht freigeben.
Nur Developer sind vom Vier-Augen-Prinzip ausgenommen.
Rollenänderungen werden erst mit ihrer veröffentlichten Policy wirksam; ein
Entwurf kann daher keine zusätzlichen Rechte vergeben. Leser sehen den
Menüpunkt **Administration** nicht. Ein übergeordneter
Verantwortungsbereich besitzt lesenden Zugriff auf seine untergeordneten
Bereiche.

## Darstellung und Dark Mode

Die Schaltfläche **Dark Mode** (im dunklen Modus **Light Mode**) wechselt die
Darstellung. Die Auswahl gilt auch für Anmeldung, Administration, Changelog und
Kennwortseiten und bleibt im verwendeten Browser gespeichert. Solange noch
keine Auswahl getroffen wurde, folgt Policy-Web automatisch der Hell-/Dunkel-
Einstellung des Betriebssystems.

## Policies verwalten

Administratoren, Bearbeiter, Reviewer, Deployer und Developer öffnen nach der Anmeldung
den Menüpunkt **Administration**; die Oberfläche blendet nicht erlaubte Aktionen
rollenabhängig aus.

### Benutzer

- Die E-Mail-Adresse ist gleichzeitig der Anmeldename.
- Lokale Identitäten werden zunächst ohne Credential veröffentlicht. Danach
  aktiviert der Benutzer sein Kennwort über `passwd.html`; Administratoren
  können dafür alternativ das `create-user`-Werkzeug verwenden.
- Speichern, Staging, Veröffentlichung und Policy-Rollback verändern niemals
  lokale Kennwörter. Drafts und Revisionen enthalten weder Klartext noch Hash.
- Bei LDAP-Benutzern sind ausschließlich E-Mail-Adresse und Policy-Rolle
  editierbar; Verzeichnis-ID, Benutzername, Quelle und Aktivstatus bleiben
  serverseitig geschützt.
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
- Regeln lassen sich in einen anderen Dienst kopieren oder verschieben. Eine
  Kopie erhält serverseitig eine neue stabile Regel-ID; beim Verschieben bleibt
  sie erhalten.
- Der Regelname wird händisch vergeben, muss innerhalb der Policy eindeutig
  sein und darf höchstens 35 Zeichen aus Buchstaben, Ziffern, `_` und `-`
  enthalten. Das Backend validiert den Namen bei Speichern, Staging und
  Veröffentlichung, erzeugt ihn aber nicht neu.
- Interne Altbestandsfelder für Naming, Mandanten, Zielkontexte und Lifecycle
  bleiben beim Bearbeiten bestehender Regeln unverändert erhalten, werden in
  der normalen Oberfläche jedoch nicht mehr angezeigt oder verlangt.
- Die frühere Funktion „User expandieren“ ist vollständig entfernt. Detail- und
  Suchansichten zeigen die tatsächlich an der Regel gespeicherten Quellen und
  Ziele.

### Entwurf, Staging, Freigabe und Deployment

1. **Entwurf speichern** speichert den aktuellen Arbeitsstand mit einer
   Versionsnummer, ändert aber nicht die aktive Policy.
2. **Staging prüfen** verlangt Kommentar und Change-Referenz, validiert die
   Policy, bewertet Risiken und friert die exakten Deployment-Commands mit
   einem Plan-Hash ein.
3. Eine zweite Person mit Reviewer- oder Administratorrolle prüft den
   strukturierten Vorher-/Nachher-Diff, die feldgenauen Änderungen einschließlich
   der manuellen Regelnamen, Risiken, Validierung und
   Command-Vorschau. Sie kann freigeben oder mit Pflichtkommentar ablehnen.
   Developer dürfen diese Entscheidung auch für eigene Revisionen und Anträge
   treffen.
4. Die Freigabe veröffentlicht exakt die geprüfte Revision. Policy, Validation
   und Deployment-Plan sind gemeinsam an den Approval-Hash gebunden.
5. Ein Deployer, Administrator oder Developer kann anschließend das Deployment starten.
   Vor der ersten Mutation werden Ziel, Scope, FortiOS-Version, Policy-Anker
   und Geräte-Ist-Zustand geprüft. Jeder Schritt wird verifiziert; bei einem
   Fehler erfolgt ein automatischer Best-effort-Rollback aus vollständigen
   Snapshots.

Ändern sich Entwurf, Basisrevision oder Zielkonfiguration zwischen Staging,
Freigabe und Deployment, wird der Vorgang abgebrochen und muss neu gestaged
werden. Frühere, ausstehende, abgelehnte und veröffentlichte Revisionen sind in
der Historie einsehbar. Ein Rollback erzeugt immer einen neuen Entwurf und eine
neue prüfpflichtige Revision; nur ein Developer darf diese selbst entscheiden.

Solange eine veröffentlichte, ausführbare Revision nicht auf allen gebundenen
FortiGate-Zielen erfolgreich ausgerollt wurde, ist die Veröffentlichung der
nächsten Revision gesperrt. Dadurch bleibt die vorherige Publikation zugleich
die nachweisliche Geräte-Baseline für den nächsten Delta-Plan. Änderungen an
Zielmenge, VDOM, Endpoint oder Preview-/Deployment-Status gelten als explizite
Gerätemigration und werden vom normalen Policy-Workflow abgewiesen.

Bei einer Aktualisierung von einer Altinstallation ohne unveränderlichen,
verifizierten Deployment-Plan wird der nächste Stage bewusst als vollständiger
Abgleich `leer → Zielstand` erzeugt. Er enthält keine angenommenen Löschungen.
Bereits vorhandene gleichnamige Geräteobjekte werden dabei nur akzeptiert,
wenn sie dem freigegebenen Zielzustand exakt entsprechen; abweichende oder
nicht eindeutig zuordenbare Objekte blockieren das Deployment.
Eine vorhandene Legacy-Policy gilt außerdem nicht als abgeschlossene
Administrator-Ersteinrichtung; die einmalige Migration wird daher mit dem
Bootstrap-Token ausdrücklich autorisiert. Erst danach steht der reguläre
Vier-Augen-Workflow zur Verfügung.

## Antragswesen

Alle angemeldeten, einem Verantwortungsbereich zugeordneten Benutzer können
im normalen Policy-Bereich fachliche Änderungen beantragen:

- In der Regelansicht erzeugen die Schaltflächen **+/− Quelle**,
  **+/− Ziel** und **+/− Port** einen Antrag für genau die ausgewählte
  Regel. Der Antrag ist an die stabile Regel-ID und die aktuelle, unveränderliche
  Basisversion gebunden; historische Ansichten sind schreibgeschützt.
- Der Menüpunkt **Antragswesen** enthält das Formular für einen neuen Dienst
  und die Statusübersicht der eigenen Anträge. Quellen und Ziele werden aus
  vorhandenen Policy-Objekten gewählt; FQDN-Objekte sind nur als Ziel zulässig.
- Wird die Basis-Policy vor dem Staging geändert oder lässt sich die beantragte
  Änderung nicht mehr eindeutig anwenden, wechselt der Antrag in den Status
  **conflict** und wird nicht stillschweigend auf eine andere Revision übertragen.

In der Administration zeigt der Tab **Antragswesen** alle Anträge mit
Antragsteller, Begründung, Payload, Status und Ereignishistorie. Ein Bearbeiter
erzeugt daraus eine normale, unveränderliche Staging-Revision. Anschließend
gelten dieselben Validierungs-, Risiko-, Approval-Hash- und Deployment-Prüfungen
wie bei manuell gepflegten Änderungen. Außer bei der Developer-Superrolle darf
weder der Ersteller der Staging-Revision noch der ursprüngliche Antragsteller
sie selbst freigeben. Ablehnungen benötigen einen Kommentar; Freigabe,
Teil-Deployment, Fehler und vollständiges
Deployment werden in der Antragsereignishistorie protokolliert. Die Admin-Liste
lädt ältere Einträge seitenweise über **Weitere Anträge laden** nach, sodass die
vollständige Historie erreichbar bleibt, ohne eine unbegrenzte Antwort zu
erzeugen. Pro Benutzer werden höchstens 200 neue Anträge innerhalb von 24
Stunden angenommen.

## Policies durchsuchen

Im Bereich **Dienste** öffnet die Schaltfläche **Suche** zwei Sucharten:

- **Dienstsuche:** Dienstname und optional Beschreibung
- **Netz-/IP-/FQDN-Suche:** IP-Adresse, FQDN, Netzobjekt, zwei Endpunkte oder Protokoll/Port

Übergeordnete und enthaltene Netze können in die Suche einbezogen werden. Die
Suche berücksichtigt sowohl direkte Quellen und Ziele als auch Dienste mit
separaten Benutzern.

## Geräte und Routing analysieren

Für Administratoren, Bearbeiter, Reviewer, Deployer und Developer steht in der
Hauptnavigation der Bereich **Geräte** zur Verfügung. Er zeigt den Status der
konfigurierten Fortinet-Ziele. Für ein Quell- und ein Zielnetz liest
Policy-Web die aktuellen IPv4- oder IPv6-Routingtabellen aller konfigurierten
FortiGates read-only aus und zeigt je VDOM:

- die effektiven Rückrouten zum Quellnetz,
- die effektiven Vorwärtsrouten zum Zielnetz,
- Interface, Gateway, Routingprotokoll, Distanz, Metrik, Priorität und VRF,
- ECMP-Alternativen, Blackhole-Routen und nicht erreichbare Geräte sowie
- die daraus abgeleiteten Endpunkt-, Transit- und Drop-Kandidaten.

Die Anzeige bezeichnet Firewalls bewusst als **Routing-Kandidaten**. Aus
Routingtabellen allein lassen sich die Reihenfolge mehrerer Firewalls sowie
Policy-Based Routing, SD-WAN-Entscheidungen, NAT, Firewall-Policies und der
tatsächliche Rückweg nicht zweifelsfrei bestimmen. Dafür wären zusätzliche
Topologie- und Nachbarschaftsdaten erforderlich.

Die Analyse ist immer auf genau eine VRF begrenzt. Im Formular ist standardmäßig
VRF `0` ausgewählt; passend zu FortiOS 7.4 kann für getrennte Routinginstanzen
eine VRF-ID zwischen `0` und `251` angegeben werden.

Administratoren und Developer können FortiGates direkt in der Geräteansicht anlegen,
bearbeiten, deaktivieren, testen und löschen. Erforderlich sind ein Name, ein
HTTPS-Endpunkt und ein API-Token. Beim Anlegen wird die vollständige paginierte
VDOM-Liste automatisch gelesen und jedes VDOM als eigenes Routingziel angelegt;
für interne PKI kann zusätzlich ein CA-Zertifikat im PEM-Format hinterlegt
werden. Das Token wird nie wieder an
den Browser zurückgegeben und liegt ausschließlich in Dateien mit Modus `0600`
unter dem persistenten `policyweb-users`-Volume. Das Credential-Verzeichnis hat
Modus `0700`. Eine Änderung der Ziel-URL oder des CA-Vertrauensankers verlangt
immer einen neuen Token.

Webverwaltete FortiGates dienen ausschließlich Status- und Routingabfragen und
haben keinen Deployment-Zugriff. Deployment-Ziele bleiben bewusst statisch in
`fortinet_targets` mit referenzierten Umgebungsvariablen konfiguriert; sie werden
in der Geräteansicht schreibgeschützt angezeigt. Für jede Routinganalyse muss
ein eindeutiges `vdom` gesetzt sein. Der verwendete FortiGate-API-Benutzer
benötigt read-only Zugriff auf die Router-Monitor-API. Token und ungefilterte
Geräteantworten werden nicht an den Browser weitergereicht.

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

## Fortinet-Staging und Deployment konfigurieren

Policy-Web erzeugt im Staging deterministische CLI- und REST-Kommandos für die
konfigurierten Zielkontexte. Reale Deployments sind bewusst auf FortiGate mit
FortiOS `7.4.x` begrenzt und werden aktuell gegen FortiOS `7.4.12` betrieben.
Der Preflight liest die Geräteversion vor jeder Mutation und bricht bei jeder
anderen Minor-Version ab. FortiManager-Pläne können geprüft werden, bleiben aber
ohne explizites Managed-Device-Installationsziel Vorschau-only.

Beispiel für `fortinet_targets` in `policyweb.conf`:

```json
{
  "fortinet_targets": [
    {
      "name": "edge-1",
      "type": "fortigate",
      "url": "https://edge-1.example.net",
      "vdom": "root",
      "target_contexts": ["prod-root"],
      "zone_interfaces": {
        "EXT": "port1",
        "GDMZ": "port2",
        "IDMZ": "port3"
      },
      "policy_insert_before": "POLICYWEB-END",
      "allow_deploy": true,
      "token_env": "EDGE_1_API_TOKEN"
    },
    {
      "name": "manager-1-preview",
      "type": "fortimanager",
      "url": "https://fmg.example.net",
      "adom": "production",
      "policy_package": "edge-policy",
      "target_contexts": ["shared-edge"],
      "zone_interfaces": {
        "EXT": "wan",
        "GDMZ": "gdmz"
      },
      "allow_deploy": false,
      "username_env": "FMG_API_USER",
      "password_env": "FMG_API_PASSWORD"
    }
  ]
}
```

`policy_insert_before` bezeichnet eine bereits vorhandene, eindeutig benannte
Anker-Policy. Policy-Web verkettet den gesamten freigegebenen Policy-Block:
die letzte Regel liegt vor dem konfigurierten Anker, jede vorherige Regel vor
ihrem freigegebenen Nachfolger. Das Staging zeigt die normalisierte Ziel-URL,
den exakten VDOM/Scope, die Semantik- und Ausführungsmodell-Version sowie für
jeden REST-Zweig das rohe CMDB-JSON an, das ohne zusätzliches `data`-Envelope
gesendet wird. Ohne Anker ist `allow_deploy: true` ungültig. Updates behalten
ihre bestehende Position.

Die Ausführung erfolgt in sicherheitsgerichteten Phasen: Zuerst werden
content-addressierte Address-/Address6-/Service-Objekte geprüft oder angelegt.
Neue Policies entstehen anschließend deaktiviert und werden von unten nach
oben positioniert. Danach werden gewünschte DENY-Policies von oben nach unten
finalisiert, veraltete ACCEPT-Policies entfernt und erst dann gewünschte
ACCEPT-Policies finalisiert. Nicht mehr gewünschte DENY-Policies werden zuletzt
gelöscht. Jeder mutierende Schritt wird erneut gelesen und verifiziert; bei
einem Fehler wird anhand der gebundenen Snapshots kompensiert. So bleiben die
First-Match-Reihenfolge und die DENY-vor-ACCEPT-Schranke auch bei mehreren
gleichzeitigen Neuanlagen deterministisch. Ein Rollback beginnt erst, wenn die
Post-States aller betroffenen Schritte eindeutig abgeglichen wurden. Gelöschte
Policies werden zunächst deaktiviert mit ihrer bisherigen `policyid` und
Position wiederhergestellt; DENY-Regeln werden vor ACCEPT-Regeln reaktiviert,
neu angelegte DENYs zuletzt entfernt und Objekte erst nach den Policies
kompensiert.

Große CMDB-Tabellen werden vollständig über `start`/`count` gelesen. Policy-Web
übernimmt eine paginierte Momentaufnahme nur, wenn alle Seiten dieselbe
FortiOS-Revision melden, die MKeys eindeutig bleiben und die Seitenfolge
vollständig ist; andernfalls wird vor einer Mutation abgebrochen. Eine
Match-Änderung an einer bereits aktiven DENY-Policy wird nicht in-place
ausgeführt. Dafür wird die Regel zuerst mit neuer Regelidentität kopiert und
die alte Regel im selben geprüften Entwurf entfernt, sodass der Ersatz
deaktiviert vorbereitet werden kann.

Die Commands legen ausschließlich die benötigten Address-, Address6- und
Custom-Service-Objekte sowie Einträge in der einheitlichen FortiOS-7.4-Tabelle
`firewall policy` an. IPv6-Regeln verwenden dort `srcaddr6` und `dstaddr6`.
Address- und Service-Objektnamen sind aus Semantikversion, Typ und finalem
REST-Inhalt abgeleitet; eine fachliche oder Renderer-Änderung erzeugt deshalb
ein neues Objekt, statt die Bedeutung eines von einer aktiven Policy
verwendeten Objekts vorzeitig in-place zu ändern.
Beim Entfernen einer Regel wird nur die exakt erwartete, zuvor veröffentlichte
Policy gelöscht und nur, wenn ihr Geräte-Ist-Zustand noch übereinstimmt.
Address- oder Service-Objekte werden nie automatisch gelöscht, weil sie von
geräte-lokalen Regeln geteilt sein können.

Passende Zugangsdaten in `.env`:

```dotenv
POLICYWEB_FORTIGATE_READ_ONLY=true
EDGE_1_API_TOKEN=fortigate-api-token
FMG_API_USER=api-user
FMG_API_PASSWORD=api-kennwort
```

Mit `POLICYWEB_FORTIGATE_READ_ONLY=true` bleiben FortiGate-Status,
Routinganalyse, VDOM-Erkennung, Staging-Vorschau und Drift-Prüfung verfügbar;
alle `POST`-, `PUT`- und `DELETE`-Anfragen an FortiGate werden jedoch vor
Token-Auflösung und Netzwerkzugriff blockiert. Der globale Schalter überstimmt
`allow_deploy: true`, ohne den freigegebenen Plan oder dessen Hash zu verändern.
Nur für ein beabsichtigtes Deployment wird der Wert auf `false` gesetzt. Fehlt
die Variable, bleibt das bisherige schreibende Verhalten erhalten; ungültige
Werte verhindern aus Sicherheitsgründen den Anwendungsstart.

Der FortiGate-Token sollte einem eigenen REST-API-Administrator mit minimalen
Rechten und Trusted Hosts gehören. Secrets werden nicht in `policyweb.conf`,
Staging-Plänen oder Audit-Ereignissen gespeichert. Die Ziel-URL muss HTTPS
verwenden. Für eine interne Zertifizierungsstelle kann eine PEM-Datei read-only
gemountet und über `ca_file` referenziert werden. `insecure_skip_verify` wird
für alle authentifizierten Fortinet-Ziele generell abgelehnt: Auch reine
Status- oder Drift-Abfragen dürfen Bearer-Token oder FortiManager-Zugangsdaten
nie über eine ungeprüfte TLS-Verbindung senden.

Nach einer Änderung von `policyweb.conf` oder `.env` muss der Container neu
erstellt werden:

```sh
docker compose up -d --force-recreate policyweb
```

Status, Staging-Preview, Deployment und Drift-Prüfung stehen im Admin-Panel zur
Verfügung. Der reine Status ist für angemeldete Benutzer außerdem unter
`/backend/fortinet/status` abrufbar.

## Kennwort per Kommandozeile aktivieren oder zurücksetzen

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
- das Docker-Volume `policyweb-users` mit lokalen Anmeldedaten und den serverseitigen FortiGate-Tokens
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

Hinter dem vertrauenswürdigen Reverse-Proxy müssen anschließend in `.env` diese
Werte gesetzt und der Container neu erstellt werden:

```dotenv
POLICYWEB_COOKIE_SECURE=true
POLICYWEB_TRUST_PROXY_HEADERS=true
```

Der Proxy muss eingehende `X-Forwarded-*`-Header von Clients verwerfen und
selbst korrekt setzen. Ohne direkten, kontrollierten Proxy darf
`POLICYWEB_TRUST_PROXY_HEADERS` nicht aktiviert werden.

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

Die Administration ist nur für Bearbeiter, Reviewer, Deployer, Administratoren
und Developer sichtbar. Leser sehen ausschließlich die normalen Ansichten.

### Sitzung ist abgelaufen

Zur Startseite wechseln und erneut anmelden. Erscheint die Meldung unmittelbar
nach einer korrekten Anmeldung, muss die E-Mail-Adresse in der veröffentlichten
Policy einem Verantwortungsbereich als Benutzer oder Bereichsadministrator
zugeordnet sein; für Developer gilt diese Bereichszuordnung nicht. Ein Verlust
des Session-Volumes meldet alle Benutzer ab,
beschädigt aber keine Policy-Daten.

### Netze, IP-Adressen oder Dienste fehlen

Prüfen, ob die Änderung als Diff bestätigt und veröffentlicht wurde, ob der
richtige Verantwortungsbereich ausgewählt ist und ob die Ressource diesem oder
einem untergeordneten Bereich gehört.

### Ein Staging kann nicht bestätigt werden

Wurde seit dem Staging bereits eine andere Policy veröffentlicht, ist die
Basisrevision veraltet. Den Entwurf erneut prüfen und neu stagen. Creator und
Approver müssen verschiedene Konten sein; außerdem werden Revisionen ohne
Kommentar, Change-Referenz, Validation und unveränderten Deployment-Plan
serverseitig abgelehnt.

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
- LDAP ausschließlich per LDAPS und mit einem lesenden Sync-Servicekonto nutzen.
- Bootstrap-Token nach der Ersteinrichtung entfernen.
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
