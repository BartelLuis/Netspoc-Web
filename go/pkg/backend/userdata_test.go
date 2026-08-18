package backend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetUserPassword(t *testing.T) {
	dir := t.TempDir()
	if err := SetUserPassword(dir, "admin@example.test", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	store, err := GetUserStore(filepath.Join(dir, "admin@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.CheckPassword("correct horse battery staple") || store.CheckPassword("wrong") {
		t.Fatal("stored password does not match")
	}
	info, err := os.Stat(filepath.Join(dir, "admin@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("user file mode = %v", info.Mode().Perm())
	}
}

func TestSetUserPasswordRejectsInvalidInput(t *testing.T) {
	for _, email := range []string{"", "guest", "../admin", "not-an-email", "Name <admin@example.test>"} {
		if err := SetUserPassword(t.TempDir(), email, "password"); err == nil {
			t.Errorf("email %q was accepted", email)
		}
	}
	if err := SetUserPassword(t.TempDir(), "admin@example.test", ""); err == nil {
		t.Error("empty password was accepted")
	}
}
