package backend

import "testing"

// seedPolicyTestAccounts initializes the account store explicitly for tests
// that do not exercise the setup claim. A normal policy publication must never
// be used as an account bootstrap mechanism.
func seedPolicyTestAccounts(t *testing.T, s *state, users ...editableUser) {
	t.Helper()
	db, err := s.policyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := s.seedSetupAccountsTx(tx, users, "test-bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
