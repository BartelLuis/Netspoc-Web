package backend

import (
	"net/http"
)

func (s *state) getServicesAndRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwnerAccess(w, r, r.FormValue("active_owner")) {
		return
	}
	serviceRecords := s.generateServiceList(r)

	// If no services are found, return an empty result.
	result := []jsonMap{}

	for _, service := range serviceRecords {
		service, ok := service["name"].(string)
		if !ok {
			http.Error(w, "Invalid service name", http.StatusInternalServerError)
			return
		}
		rules := s.expandRules(r, service)

		// Adapt multi service result.
		for _, rule := range rules {
			// The service name on the rule is needed for grouping in the frontend.
			rule["service"] = service
			result = append(result, rule)
		}
	}
	writeRecords(w, result)
}
