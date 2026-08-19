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

### Geändert

- Die Willkommensseite zeigt ausschließlich das Changelog.
- Regeln sind pro Dienst einklappbar und werden in einer übersichtlichen Untertabelle bearbeitet.

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
