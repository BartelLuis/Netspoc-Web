package backend

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type maintenanceSettings struct {
	Enabled   bool   `json:"enabled"`
	Message   string `json:"message"`
	StartsAt  string `json:"starts_at,omitempty"`
	EndsAt    string `json:"ends_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func ensureMaintenanceTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS maintenance_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		enabled INTEGER NOT NULL,
		message TEXT NOT NULL,
		starts_at TEXT NOT NULL DEFAULT '',
		ends_at TEXT NOT NULL DEFAULT '',
		updated_by TEXT NOT NULL DEFAULT '',
		updated_at TEXT NOT NULL
	)`)
	return err
}

func (s *state) configuredMaintenanceSettings() maintenanceSettings {
	return maintenanceSettings{Enabled: s.config.MaintenanceMode, Message: strings.TrimSpace(s.config.MaintenanceMessage)}
}

func failClosedMaintenanceSettings() maintenanceSettings {
	return maintenanceSettings{Enabled: true}
}

func (s *state) loadMaintenanceSettings() (maintenanceSettings, error) {
	db, err := s.policyDB()
	if err != nil {
		return maintenanceSettings{}, fmt.Errorf("open policy database: %w", err)
	}
	defer db.Close()
	if err := ensureMaintenanceTable(db); err != nil {
		return maintenanceSettings{}, fmt.Errorf("initialize maintenance settings: %w", err)
	}
	var settings maintenanceSettings
	var enabled int
	err = db.QueryRow(`SELECT enabled, message, starts_at, ends_at, updated_by, updated_at FROM maintenance_settings WHERE id=1`).Scan(&enabled, &settings.Message, &settings.StartsAt, &settings.EndsAt, &settings.UpdatedBy, &settings.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s.configuredMaintenanceSettings(), nil
	}
	if err != nil {
		return maintenanceSettings{}, fmt.Errorf("read maintenance settings: %w", err)
	}
	if enabled != 0 && enabled != 1 {
		return maintenanceSettings{}, fmt.Errorf("read maintenance settings: invalid enabled value %d", enabled)
	}
	settings.Enabled = enabled != 0
	if err := validateMaintenanceSettings(settings); err != nil {
		return maintenanceSettings{}, fmt.Errorf("validate stored maintenance settings: %w", err)
	}
	return settings, nil
}

func parseMaintenanceTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.New("maintenance timestamps must use RFC3339")
	}
	return parsed, nil
}

func validateMaintenanceSettings(settings maintenanceSettings) error {
	start, err := parseMaintenanceTime(settings.StartsAt)
	if err != nil {
		return err
	}
	end, err := parseMaintenanceTime(settings.EndsAt)
	if err != nil {
		return err
	}
	if !start.IsZero() && !end.IsZero() && !end.After(start) {
		return errors.New("maintenance ends_at must be after starts_at")
	}
	return nil
}

func maintenanceActiveAt(settings maintenanceSettings, now time.Time) bool {
	// Invalid persisted scheduling data must never silently disable the safety
	// gate. loadMaintenanceSettings reports the error to administrative callers;
	// this direct helper remains fail-closed as a second line of defense.
	if err := validateMaintenanceSettings(settings); err != nil {
		return true
	}
	if !settings.Enabled {
		return false
	}
	start, _ := parseMaintenanceTime(settings.StartsAt)
	end, _ := parseMaintenanceTime(settings.EndsAt)
	if !start.IsZero() && now.Before(start) {
		return false
	}
	if !end.IsZero() && !now.Before(end) {
		return false
	}
	return true
}

func (s *state) maintenanceActive() (bool, maintenanceSettings, error) {
	settings, err := s.loadMaintenanceSettings()
	if err != nil {
		return true, failClosedMaintenanceSettings(), err
	}
	return maintenanceActiveAt(settings, time.Now().UTC()), settings, nil
}

func (s *state) saveMaintenanceSettings(settings maintenanceSettings, actor string) error {
	settings.Message = strings.TrimSpace(settings.Message)
	settings.StartsAt = strings.TrimSpace(settings.StartsAt)
	settings.EndsAt = strings.TrimSpace(settings.EndsAt)
	if err := validateMaintenanceSettings(settings); err != nil {
		return err
	}
	db, err := s.policyDB()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := ensureMaintenanceTable(db); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Exec(`INSERT INTO maintenance_settings(id, enabled, message, starts_at, ends_at, updated_by, updated_at)
		VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, message=excluded.message,
		starts_at=excluded.starts_at, ends_at=excluded.ends_at, updated_by=excluded.updated_by, updated_at=excluded.updated_at`,
		settings.Enabled, settings.Message, settings.StartsAt, settings.EndsAt, strings.ToLower(actor), now)
	return err
}

func (s *state) adminMaintenance(w http.ResponseWriter, r *http.Request) {
	actor := getEmailFromSession(r)
	p := s.authorizationPolicy()
	if !hasPolicyRole(p, actor, "admin") {
		s.audit(actor, "maintenance.update", "denied", nil)
		writeError(w, "Policy administrator role required", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		active, settings, err := s.maintenanceActive()
		if err != nil {
			log.Printf("load maintenance settings: %v", err)
			writeError(w, "Wartungseinstellungen sind nicht verf\u00fcgbar; der sichere Wartungsmodus ist aktiv", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"success": true, "active": active, "settings": settings})
	case http.MethodPost:
		var settings maintenanceSettings
		if err := decodeJSONRequest(w, r, 1<<20, &settings); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveMaintenanceSettings(settings, actor); err != nil {
			s.audit(actor, "maintenance.update", "failed", map[string]any{"error": err.Error()})
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		active, saved, err := s.maintenanceActive()
		if err != nil {
			s.audit(actor, "maintenance.update", "failed", map[string]any{"error": err.Error()})
			log.Printf("reload maintenance settings after update: %v", err)
			writeError(w, "Wartungseinstellungen sind nicht verf\u00fcgbar; der sichere Wartungsmodus ist aktiv", http.StatusServiceUnavailable)
			return
		}
		s.audit(actor, "maintenance.update", "success", map[string]any{"active": active, "settings": saved})
		writeJSON(w, map[string]any{"success": true, "active": active, "settings": saved})
	default:
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
