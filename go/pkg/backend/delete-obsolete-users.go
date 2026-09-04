// Compare users found in /home/netspocweb/users to list of admins and watchers
// found in json export data (/home/netspocweb/export/current) from netspoc.
// Delete those that are not found in export data.

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func DeleteObsoleteUsers() {
	config := LoadConfig()
	s := &state{
		config: config,
		cache:  newCache(config.NetspocData, 8),
	}
	userStoreDir := config.UserDir
	emailToOwners := s.loadEmail2Owners()
	accounts, _, err := s.accountCatalog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read managed user accounts: %v\n", err)
		return
	}
	managed := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		managed[strings.ToLower(account.Email)] = true
	}
	d, err := os.Open(userStoreDir)
	if err != nil {
		os.Exit(1)
	}
	defer d.Close()
	files, err := d.Readdirnames(-1)
	if err != nil {
		os.Exit(1)
	}
	now := time.Now()
	for _, email := range files {
		if !strings.Contains(email, "@") {
			continue
		}
		domain := strings.SplitN(email, "@", 2)[1]
		if managed[strings.ToLower(email)] {
			continue
		}
		wildcard := "[all]@" + domain
		if _, ok := emailToOwners[wildcard]; ok {
			continue
		}
		if _, ok := emailToOwners[email]; ok {
			continue
		}
		filePath := filepath.Join(userStoreDir, email)
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 7*24*time.Hour {
			if err := os.Remove(filePath); err != nil {
				fmt.Fprintf(os.Stderr, "Could not unlink %s: %v\n", filePath, err)
			}
		}
	}
}
