package backend

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func (s *state) getOwners(w http.ResponseWriter, r *http.Request) {
	// Return all owners that the logged-in user is authorized to access.
	// This is used to populate the owner selection dropdown.
	email := getEmailFromSession(r)
	authorizedOwners := s.findAuthorizedOwners(email)
	if len(authorizedOwners) == 0 {
		writeRecords(w, []jsonMap{})
		return
	}
	// Return as a list of {"name": owner}.
	var owners []map[string]string
	for _, owner := range authorizedOwners {
		owners = append(owners, map[string]string{"name": owner})
	}
	writeRecords(w, owners)
}

func (s *state) getOwner(w http.ResponseWriter, r *http.Request) {
	session := GetGoSession(r)
	ow := getOwnerFromSession(r)
	email := getEmailFromSession(r)
	authorizedOwners := s.findAuthorizedOwners(email)
	if len(authorizedOwners) == 0 {
		writeRecords(w, []jsonMap{})
		return
	}
	if err := s.bindRequestedPolicyVersionForAnyOwner(r, authorizedOwners); err != nil {
		writeError(w, "Policy revision is unavailable", http.StatusForbidden)
		return
	}
	// Selected owner was stored before.
	if ow != "" && slices.Contains(authorizedOwners, ow) {
		writeRecords(w, []jsonMap{{"name": ow}})
		return
	}
	/* Automatically select the authorized owner with the largest effective
	service list. The list already contains hierarchy descendants and explicit
	read grants. If an authorized parent has an even larger effective list,
	extended_by may still promote that parent. */

	// Compare effective service lists, not only direct service ownership. This
	// makes an authorized read_all/read_owners collector the natural default.
	histPar := s.getHistoryParamOrCurrentPolicy(r)
	bestOwner := authorizedOwners[0]
	maxServices := len(s.loadServiceLists(histPar, bestOwner).Owner)
	for _, ow := range authorizedOwners[1:] {
		count := len(s.loadServiceLists(histPar, ow).Owner)
		if count > maxServices {
			maxServices = count
			bestOwner = ow
		}
	}
	if bestOwner != "" {
		extBy := s.loadExtendedBy(histPar, bestOwner)
		maxSize := maxServices
		for _, entry := range extBy {
			ow := entry.Name
			sl := s.loadServiceLists(histPar, ow)
			size := len(sl.Owner)
			if size > maxSize {
				if slices.Contains(authorizedOwners, ow) {
					maxSize = size
					bestOwner = ow
				}
			}
		}
		session.Put("owner", bestOwner)
		writeRecords(w, []jsonMap{{"name": bestOwner}})
		return
	}
	writeRecords(w, []jsonMap{})
}

func (s *state) findAuthorizedOwners(email string) []string {
	m := s.loadEmail2Owners()
	if email == "" {
		return []string{}
	}
	_, dom, _ := strings.Cut(email, "@")
	wildcard := "[all]@" + dom
	result := slices.Concat(m[wildcard], m[email])
	slices.Sort(result)
	result = slices.Compact(result)
	return result
}

// Validate active owner.
// Email could be removed from any owner role at any time in netspoc data.
func (s *state) validateOwner(r *http.Request, ownerNeeded bool) error {
	activeOwner := r.FormValue("active_owner")
	if activeOwner != "" {
		if !ownerNeeded {
			return errors.New("must not send parameter 'active_owner'")
		}
		if !s.canAccessOwner(r, activeOwner) {
			return errors.New("Not authorized to access owner '" + activeOwner + "'")
		}
	} else {
		if ownerNeeded {
			return errors.New("missing parameter 'active_owner'")
		}
	}
	return nil
}

func (s *state) canAccessOwner(r *http.Request, owner string) bool {
	email := getEmailFromSession(r)
	for _, authorizedOwner := range s.findAuthorizedOwners(email) {
		if owner == authorizedOwner {
			return true
		}
	}
	return false
}

// requestedActiveOwner returns the explicit request parameter, or the owner
// stored in the session for endpoints which historically allowed that fallback.
func requestedActiveOwner(r *http.Request) string {
	owner := r.FormValue("active_owner")
	if owner == "" {
		owner = getOwnerFromSession(r)
	}
	return owner
}

// requireOwnerAccess is the common authorization gate for every endpoint that
// reads owner-scoped policy data. The current policy controls authorization,
// including when an older policy revision is being displayed.
func (s *state) requireOwnerAccess(w http.ResponseWriter, r *http.Request, owner string) bool {
	if owner == "" {
		writeError(w, "missing parameter 'active_owner'", http.StatusBadRequest)
		return false
	}
	if !s.canAccessOwner(r, owner) {
		writeError(w, "Not authorized to access owner '"+owner+"'", http.StatusForbidden)
		return false
	}
	if err := s.bindRequestedPolicyVersion(r, owner); err != nil {
		writeError(w, "Policy revision is unavailable", http.StatusForbidden)
		return false
	}
	return true
}

// ownerTargetExists validates secondary owner parameters used to load contact
// information. Such a target may differ from active_owner for multi-owner
// services. Strict name validation also prevents directory traversal.
func (s *state) ownerTargetExists(owner string) bool {
	if !policyNameRE.MatchString(owner) {
		return false
	}
	if info, err := os.Stat(filepath.Join(s.config.NetspocData, "current", "owner", owner)); err != nil || !info.IsDir() {
		return false
	}
	return true
}

func (s *state) requireOwnerTarget(w http.ResponseWriter, owner string) bool {
	if !s.ownerTargetExists(owner) {
		writeError(w, "Owner is unavailable", http.StatusForbidden)
		return false
	}
	return true
}
