package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

var userStoreLocks sync.Map

func lockUserStore(userFile string) func() {
	key := filepath.Clean(userFile)
	value, _ := userStoreLocks.LoadOrStore(key, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

var accountEmailRE = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func canonicalAccountEmail(value string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" || email == "guest" || len(email) > 254 || strings.ContainsAny(email, `/\`) || !accountEmailRE.MatchString(email) {
		return "", fmt.Errorf("invalid account email")
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) > 64 || strings.HasPrefix(parts[0], ".") || strings.HasSuffix(parts[0], ".") || strings.Contains(parts[0], "..") {
		return "", fmt.Errorf("invalid account email")
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", fmt.Errorf("invalid account email")
	}
	return email, nil
}

func safeUserFile(userDir, email string) (string, error) {
	canonical, err := canonicalAccountEmail(email)
	if err != nil {
		return "", err
	}
	root, err := filepath.Abs(userDir)
	if err != nil {
		return "", err
	}
	file := filepath.Join(root, canonical)
	relative, err := filepath.Rel(root, file)
	if err != nil || relative != canonical || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid user file path")
	}
	return file, nil
}

const (
	argonMemory      = 19 * 1024
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLength  = 16
	argonKeyLength   = 32
)

// SetUserPassword creates or updates a local user account. It is shared by the
// web registration flow and the container administration command.
func SetUserPassword(userDir, email, password string) error {
	userFile, err := safeUserFile(userDir, email)
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := encodePassword(password)
	if err != nil {
		return err
	}
	return updateUserStore(userFile, true, func(store *UserStore) (bool, error) {
		store.Hash = hash
		return true, nil
	})
}

type UserStore struct {
	Hash     string   `json:"hash"`
	SendDiff []string `json:"send_diff"`
}

type SSHAEncoder struct{}

// Encode takes a raw password phrase as []byte input and encodes it using
// the SSHAEncoder.
// It returns the encoded password as a byte slice or an error if the
// encoding fails.
func (enc SSHAEncoder) Encode(rawPassPhrase []byte) ([]byte, error) {
	hash := makeSHA256Hash(rawPassPhrase, makeSalt())
	b64 := base64.StdEncoding.EncodeToString(hash)
	return fmt.Appendf(nil, "{SSHA256}%s", b64), nil
}

func (enc SSHAEncoder) EncodeAsString(rawPassPhrase []byte) (string, error) {
	hash := makeSHA256Hash(rawPassPhrase, makeSalt())
	b64 := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("{SSHA256}%s", b64), nil
}

// MatchesSHA256 matches the encoded password and the raw password
func (enc SSHAEncoder) MatchesSHA256(encodedPassPhrase, rawPassPhrase []byte) bool {
	//strip the {SSHA256} prefix
	if len(encodedPassPhrase) < 9 || string(encodedPassPhrase[:9]) != "{SSHA256}" {
		return false
	}
	//decode the base64 part
	eppS := string(encodedPassPhrase)[9:]
	hash, err := base64.StdEncoding.DecodeString(eppS)
	if err != nil || len(hash) < sha256.Size+4 {
		return false
	}
	salt := hash[len(hash)-4:]

	sha256 := sha256.New()
	sha256.Write(rawPassPhrase)
	sha256.Write(salt)
	sum := sha256.Sum(nil)

	return bytes.Equal(sum, hash[:len(hash)-4])
}

func encodePassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func matchesArgon2(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	// Bound parameters read from disk before allocating memory.
	if memory < 8*1024 || memory > 256*1024 || iterations == 0 || iterations > 10 || parallelism == 0 || parallelism > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// makeSalt make a 4 byte array containing random bytes.
func makeSalt() []byte {
	sbytes := make([]byte, 4)
	rand.Read(sbytes)
	return sbytes
}

// makeSSHAHash make hasing using SHA-256 with salt.
// This is not the final output though. You need to append {SSHA}
// string with base64 of this hash.
func makeSHA256Hash(passphrase, salt []byte) []byte {
	sha256 := sha256.New()
	sha256.Write(passphrase)
	sha256.Write(salt)
	h := sha256.Sum(nil)
	return append(h, salt...)
}

// generatePassword generates a SHA256 hash of the given password
func (u *UserStore) GenerateSaltedHashFromPassword(password string) {
	hash := makeSHA256Hash([]byte(password), makeSalt())
	u.Hash = hex.EncodeToString(hash[:])
}

// CheckPassword checks if the given password matches the stored hash
func (u *UserStore) CheckPassword(password string) bool {
	if strings.HasPrefix(u.Hash, "$argon2id$") {
		return matchesArgon2(u.Hash, password)
	}
	encoder := SSHAEncoder{}
	rawPassword := []byte(password)
	return encoder.MatchesSHA256([]byte(u.Hash), rawPassword)
}

// CheckPasswordAndMigrate transparently upgrades a valid legacy SSHA256 hash
// after login. Existing accounts remain usable without a bulk password reset.
func (u *UserStore) CheckPasswordAndMigrate(password, userFile string) (bool, error) {
	unlock := lockUserStore(userFile)
	defer unlock()

	// Re-read after acquiring the per-user lock. A concurrent password reset
	// must never be overwritten by a migration based on a stale in-memory hash.
	current, err := getUserStoreUnlocked(userFile)
	if err != nil {
		return false, err
	}
	*u = *current
	if !current.CheckPassword(password) {
		return false, nil
	}
	if strings.HasPrefix(current.Hash, "$argon2id$") {
		return true, nil
	}
	hash, err := encodePassword(password)
	if err != nil {
		return false, err
	}
	current.Hash = hash
	if err := current.writeToFileAtomic(userFile); err != nil {
		return false, err
	}
	*u = *current
	return true, nil
}

// readFromFile reads the UserStore data from a JSON file
func (u *UserStore) ReadFromFile(userFile string) error {
	file, err := os.Open(userFile)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, u)
}

// writeToFile writes the UserStore data to a JSON file
func (u *UserStore) WriteToFile(userFile string) error {
	unlock := lockUserStore(userFile)
	defer unlock()
	return u.writeToFileAtomic(userFile)
}

func (u *UserStore) writeToFileAtomic(userFile string) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}

	// Ensure the directory exists
	dir := filepath.Dir(userFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(userFile)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, userFile); err != nil {
		return err
	}
	committed = true
	return os.Chmod(userFile, 0600)
}

// updateUserStore serializes the complete read-modify-write cycle for one
// account. The callback reports whether a write is needed.
func updateUserStore(userFile string, create bool, update func(*UserStore) (bool, error)) error {
	unlock := lockUserStore(userFile)
	defer unlock()

	store, err := getUserStoreUnlocked(userFile)
	if os.IsNotExist(err) && create {
		store = &UserStore{SendDiff: []string{}}
	} else if err != nil {
		return err
	}
	changed, err := update(store)
	if err != nil || !changed {
		return err
	}
	if store.SendDiff == nil {
		store.SendDiff = []string{}
	}
	return store.writeToFileAtomic(userFile)
}

func GetUserStore(userFile string) (*UserStore, error) {
	unlock := lockUserStore(userFile)
	defer unlock()
	return getUserStoreUnlocked(userFile)
}

func getUserStoreUnlocked(userFile string) (*UserStore, error) {
	userStore := &UserStore{}
	if err := userStore.ReadFromFile(userFile); err != nil {
		return nil, err
	}
	if userStore.SendDiff == nil {
		userStore.SendDiff = []string{}
	}
	return userStore, nil
}
