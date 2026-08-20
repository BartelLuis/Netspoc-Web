package backend

import "net/http"

// getFQDNs returns the DNS objects visible in the active responsibility
// scope. The visibility list is part of each published owner's assets so it
// also works for historical policy revisions.
func (s *state) getFQDNs(w http.ResponseWriter, r *http.Request) {
	owner := requestedActiveOwner(r)
	if !s.requireOwnerAccess(w, r, owner) {
		return
	}
	history := s.getHistoryParamOrCurrentPolicy(r)
	assets := s.loadAssets(history, owner)
	writeRecords(w, s.getCombinedObjList(assets.fqdnList, owner, history))
}
