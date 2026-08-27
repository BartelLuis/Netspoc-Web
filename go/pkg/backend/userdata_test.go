package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	if !strings.HasPrefix(store.Hash, "$argon2id$") {
		t.Fatalf("password was not stored with Argon2id: %q", store.Hash)
	}
	info, err := os.Stat(filepath.Join(dir, "admin@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("user file mode = %v", info.Mode().Perm())
	}
}

func TestLegacyPasswordIsMigratedAfterSuccessfulCheck(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "legacy@example.test")
	store := &UserStore{}
	legacy, err := (SSHAEncoder{}).EncodeAsString([]byte("legacy password"))
	if err != nil {
		t.Fatal(err)
	}
	store.Hash = legacy
	if err := store.WriteToFile(userFile); err != nil {
		t.Fatal(err)
	}
	valid, err := store.CheckPasswordAndMigrate("legacy password", userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !valid || !strings.HasPrefix(store.Hash, "$argon2id$") {
		t.Fatalf("legacy password was not migrated: valid=%v hash=%q", valid, store.Hash)
	}
	reloaded, err := GetUserStore(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.CheckPassword("legacy password") {
		t.Fatal("migrated password cannot be verified")
	}
}

func TestSetUserPasswordRejectsInvalidInput(t *testing.T) {
	for _, email := range []string{"", "guest", "../admin@example.test", `..\admin@example.test`, "not-an-email", "Name <admin@example.test>", "a..b@example.test", ".admin@example.test", "admin@example", "admin@example.test/child"} {
		if err := SetUserPassword(t.TempDir(), email, "password"); err == nil {
			t.Errorf("email %q was accepted", email)
		}
	}
	if err := SetUserPassword(t.TempDir(), "admin@example.test", ""); err == nil {
		t.Error("empty password was accepted")
	}
}

func TestCanonicalAccountEmailAndSafePath(t *testing.T) {
	email, err := canonicalAccountEmail(" Admin.User+tag@Example.TEST ")
	if err != nil || email != "admin.user+tag@example.test" {
		t.Fatalf("canonical email = %q, %v", email, err)
	}
	dir := t.TempDir()
	file, err := safeUserFile(dir, email)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(file) != dir || filepath.Base(file) != email {
		t.Fatalf("unsafe path %q", file)
	}
}

func TestGetUserStoreDoesNotCreateMissingAccount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "missing@example.test")
	if _, err := GetUserStore(file); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist, got %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("missing account file was created: %v", err)
	}
}

func TestConcurrentPasswordAndPreferenceUpdatesAreAtomic(t *testing.T) {
	dir := t.TempDir()
	const email = "parallel@example.test"
	const password = "parallel password"
	userFile := filepath.Join(dir, email)
	if err := SetUserPassword(dir, email, password); err != nil {
		t.Fatal(err)
	}

	var writers sync.WaitGroup
	var reader sync.WaitGroup
	var done atomic.Bool
	firstErr := make(chan error, 1)
	report := func(err error) {
		select {
		case firstErr <- err:
		default:
		}
	}
	reader.Add(1)
	go func() {
		defer reader.Done()
		for !done.Load() {
			if _, err := GetUserStore(userFile); err != nil {
				report(fmt.Errorf("concurrent read observed invalid store: %w", err))
				return
			}
		}
	}()

	const updates = 12
	for i := 0; i < updates; i++ {
		owner := fmt.Sprintf("owner-%02d", i)
		writers.Add(2)
		go func() {
			defer writers.Done()
			if err := SetUserPassword(dir, email, password); err != nil {
				report(err)
			}
		}()
		go func() {
			defer writers.Done()
			err := updateUserStore(userFile, false, func(store *UserStore) (bool, error) {
				store.SendDiff = append(store.SendDiff, owner)
				return true, nil
			})
			if err != nil {
				report(err)
			}
		}()
	}
	writers.Wait()
	done.Store(true)
	reader.Wait()
	select {
	case err := <-firstErr:
		t.Fatal(err)
	default:
	}

	store, err := GetUserStore(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !store.CheckPassword(password) {
		t.Fatal("concurrent preference updates lost or corrupted the password")
	}
	seen := make(map[string]bool, len(store.SendDiff))
	for _, owner := range store.SendDiff {
		seen[owner] = true
	}
	for i := 0; i < updates; i++ {
		owner := fmt.Sprintf("owner-%02d", i)
		if !seen[owner] {
			t.Fatalf("concurrent password updates lost preference %q: %v", owner, store.SendDiff)
		}
	}
}
