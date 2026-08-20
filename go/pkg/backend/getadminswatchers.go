package backend

import (
	"net/http"
	"slices"
	"strings"
)

func (s *state) getAdminsWatchers(w http.ResponseWriter, r *http.Request) {
	history := s.getHistoryParamOrCurrentPolicy(r)
	if !s.requireOwnerAccess(w, r, r.FormValue("active_owner")) {
		return
	}
	owner := r.FormValue("owner")
	if !s.requireOwnerTarget(w, owner) {
		return
	}
	watchers := s.loadWatchers(history, owner)
	admins := s.loadEmails(history, owner)
	combined := slices.Concat(watchers, admins)
	records := make([]jsonMap, 0)
	slices.SortStableFunc(combined, func(a, b emailEntry) int {
		return strings.Compare(a.Email, b.Email)
	})
	for _, e := range combined {
		records = append(records, jsonMap{
			"email": e.Email,
		})
	}
	writeRecords(w, records)
}
