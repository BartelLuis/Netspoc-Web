package backend

import (
	"net/http"
)

func (s *state) getAdmins(w http.ResponseWriter, r *http.Request) {
	activeOwner := r.FormValue("active_owner")
	if !s.requireOwnerAccess(w, r, activeOwner) {
		return
	}
	history := s.getHistoryParamOrCurrentPolicy(r)
	owner := r.FormValue("owner")
	if owner == "" {
		owner = activeOwner
	}
	if owner == "" {
		abort("Missing owner parameter")
	}
	records := make([]jsonMap, 0)
	if owner != ":unknown" {
		if !s.requireOwnerTarget(w, owner) {
			return
		}
		emails := s.loadEmails(history, owner)
		for _, e := range emails {
			records = append(records, jsonMap{
				"email": e.Email,
			})
		}
	}
	writeRecords(w, records)
}
