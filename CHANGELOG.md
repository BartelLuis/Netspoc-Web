# Changelog

Alle wichtigen Änderungen an Policy-Web werden in dieser Datei dokumentiert.

Das Format orientiert sich an „Keep a Changelog“. Neue Einträge kommen unter
„Unveröffentlicht“. Bei einer Veröffentlichung wird daraus ein Abschnitt mit
Versionsnummer und Datum.

## Unveröffentlicht

### Hinzugefügt

- Lokale Basisinformations- und Changelog-Seite auf der Startseite.
- Schraubenschlüssel-Symbol für die Administration in der Hauptnavigation.
- Tabellenbasierte Administration mit Bereichszählern, Suche und fester Aktionsleiste.
- SMTP-Konfiguration über policyweb.conf und Umgebungsvariablen.
- LDAP-Anmeldung per LDAPS und manueller Preview-/Confirm-Benutzersync.
- Aktivierbarer und planbarer Wartungsmodus; währenddessen bleibt nur der
  Administratorzugang offen.
- Serverseitige Policy-Namen mit Mandanten-, Kontext-, Zonen-, Service- und
  stabilen Regelmetadaten.
- Verbindliches Staging mit Validation, Risikoanalyse und vollständiger
  Deployment-Command-Vorschau.
- Vier-Augen-Freigabe mit Reviewer-/Deployer-Rollen, Ablehnung,
  Optimistic Locking und Audit-Protokoll.
- Strukturierter Reviewer-Diff mit vollständigen Vorher-/Nachher-Dokumenten,
  feldgenauen JSON-Pfaden und allen serverseitigen Naming-Ableitungen.
- FortiOS-7.4.x-/7.4.12-Deployment mit Versions-Preflight, vollständiger
  CMDB-Paginierung, Policy-Anker, schrittweiser Verifikation,
  sicherheitsgerichtetem Fehler-Rollback und Drift-Prüfung.
- Where-used-Prüfung, Lifecycle-Befunde und Rollback als neue prüfpflichtige
  Revision.
- Kopieren und Verschieben von Regeln zwischen Diensten.

### Geändert

- Die Willkommensseite zeigt ausschließlich das Changelog.
- Regeln sind pro Dienst einklappbar und werden in einer übersichtlichen Untertabelle bearbeitet.
- LDAP-Benutzer können lokal nur in E-Mail-Adresse und Policy-Rolle geändert
  werden; ihre Verzeichnisidentität bleibt serverseitig geschützt.
- Rollen- und Wartungsentscheidungen verwenden ausschließlich die zuletzt
  veröffentlichte Policy, nie unveröffentlichte Draft-Rechte.
- Zielkontext und automatisches Naming sind für jede veröffentlichte Regel
  verbindlich; Ablaufdaten sind ausschließlich für Regeln der Gruppe `TMP`
  zulässig.
- Lokale Kennwörter werden mit Argon2id gespeichert; bestehende SSHA-Hashes
  werden nach erfolgreicher Anmeldung migriert.

### Behoben

- Die FortiGate-Paginierung folgt auch nach leeren, limitierten Antwortfenstern
  dem `next_idx`, sodass die VDOM-Erkennung bei eingeschränkter Sichtbarkeit
  nicht vorzeitig abbricht.
- Dienstregeldetails zeigen wieder die tatsächlich gespeicherten Quellen und
  Ziele; NAT-Darstellung mutiert keine gecachten Objekte mehr.
- Session-Fixation, unsichere Benutzerdateipfade und implizite Kontoerstellung
  wurden verhindert.
- Die Policy-Validierung verhindert Konfigurationen ohne einen aktiven, einem
  Verantwortungsbereich zugeordneten Policy-Administrator.
- FortiOS-Deployments akzeptieren keine unvollständigen CMDB-Antworten und
  führen bei nicht eindeutig abgleichbarem Gerätezustand keine teilweise
  Rollback-Kompensation aus.

### Entfernt

- Die Funktion „User expandieren“ einschließlich UI und Backend-Unterstützung.
- Der alte `/admin/diff`-Bypass; Revisionen müssen über das vollständige
  Staging erzeugt werden.

## 1.0.0 - 2026-08-19

### Hinzugefügt

- SQLite-basierte Speicherung der administrierten Policy.
- Hierarchische Verantwortungsbereiche mit getrennten Rollen.
- IP-Adressen als enthaltene Ressourcen ihrer Netze.
- Diffs mit eigener Policy-ID und Bestätigungsworkflow.
- Historie der veröffentlichten Policy-Stände.
- In die Hauptanwendung integrierte Administration.

### Behoben

- Netzressourcen werden für den ausgewählten Verantwortungsbereich angezeigt.
- Alte und neue Assets-Exportformate können gelesen werden.
- Administration wird erst beim Öffnen geladen und bleibt nicht mehr sporadisch leer.
- Abmelden führt zuverlässig zur Start- und Anmeldeseite.
- Das Infofenster zeigt wieder Projektinformationen und verweist auf dieses Repository.
- Loginseite verwendet gültiges, zugänglicheres HTML und zeigt Administration nicht unangemeldet an.
- Doppelte SMTP-Empfänger werden vor dem Versand entfernt.
- SMTP-Absender werden validiert und Bcc-Header vor der Übertragung entfernt.
- Der Container-Build führt die Backend-Kerntests aus.

### Entfernt

- LDAP-Anmeldung und LDAP-Konfiguration; die Anmeldung erfolgt ausschließlich über lokale Benutzer.
