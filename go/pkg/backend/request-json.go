package backend

import (
	"encoding/json"
	"net/http"
)

// decodeJSONRequest accepts exactly one bounded JSON document. Mutating API
// endpoints use this consistently so appended data cannot be interpreted
// differently by middleware, logs, or future decoders.
func decodeJSONRequest(w http.ResponseWriter, r *http.Request, limit int64, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}
