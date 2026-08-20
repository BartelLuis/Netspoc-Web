package backend

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func (s *state) getHistoryParamOrCurrentPolicy(r *http.Request) string {
	history := r.FormValue("history")
	if history == "" {
		return s.currentPolicy()
	}
	return history
}

func (s *state) currentPolicy() string {
	return s.readPolicy()[0]["policy"]
}

func (s *state) getPolicy(w http.ResponseWriter, r *http.Request) {
	p := s.readPolicy()
	writeRecords(w, p)
}

func (s *state) readPolicy() []map[string]string {
	var result []map[string]string
	policyPath := s.config.NetspocData + "/current"
	entry, err := getPolicyFromFile(policyPath)
	if err != nil {
		return nil
	}
	entry["current"] = "1"
	result = append(result, entry)
	return result
}

func getPolicyFromFile(policyPath string) (map[string]string, error) {
	policyPath += "/POLICY"
	fileInfo, err := os.Stat(policyPath)
	if err != nil {
		return nil, fmt.Errorf("can't open %s: %v", policyPath, err)
	}

	modTime := fileInfo.ModTime()
	date := modTime.Format("2006-01-02")
	time := modTime.Format("15:04")

	file, err := os.Open(policyPath)
	if err != nil {
		return nil, fmt.Errorf("can't open %s: %v", policyPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("can't read policy name in %s", policyPath)
	}
	line := scanner.Text()

	re := regexp.MustCompile(`^# (\S+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil, fmt.Errorf("can't find policy name in %s", policyPath)
	}

	return map[string]string{
		"policy": matches[1],
		"date":   date,
		"time":   time,
	}, nil
}

func (s *state) getHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwnerAccess(w, r, r.FormValue("active_owner")) {
		return
	}
	histDirs, err := s.generateHistory(r)
	if err != nil {
		writeError(w, "Failed to get history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeRecords(w, histDirs)
}

// GetHistory retrieves the policy history for a given owner.
func (s *state) generateHistory(r *http.Request) ([]map[string]string, error) {
	owner := r.FormValue("active_owner")
	current := s.readPolicy()
	if len(current) == 0 {
		return nil, fmt.Errorf("current policy is unavailable")
	}
	currentPolicy := current[0]["policy"]
	result := []map[string]string{current[0]}

	// GUI-published policies use their immutable p... policy ID as directory
	// name. Keep every published version selectable instead of hiding all but
	// the current symlink behind the legacy date-based history convention.
	entries, err := os.ReadDir(s.config.NetspocData)
	if err != nil {
		return nil, fmt.Errorf("can't read policy directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "p") || entry.Name() == currentPolicy {
			continue
		}
		policyDir := filepath.Join(s.config.NetspocData, entry.Name())
		if _, err := os.Stat(filepath.Join(policyDir, "owner", owner)); err != nil {
			continue
		}
		policyEntry, err := getPolicyFromFile(policyDir)
		if err != nil || policyEntry["policy"] != entry.Name() {
			continue
		}
		result = append(result, policyEntry)
	}
	/* Add data from directory "history",
	   # containing a subdirecory for each revision:
	   # 2020-04-08/
	   #    POLICY
	   #    owner/$owner/
	   # 2020-04-09/
	   #    POLICY
	   #    ...
	*/

	// We take date, time from POLICY file.
	histPath := filepath.Join(s.config.NetspocData, "/history")
	if _, err := os.Stat(histPath); os.IsNotExist(err) {
		sort.SliceStable(result, func(i, j int) bool {
			return result[i]["policy"] > result[j]["policy"]
		})
		return result, nil
	}

	entries, err = os.ReadDir(histPath)
	if err != nil {
		return nil, fmt.Errorf("can't read history directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirName := entry.Name()
		re := regexp.MustCompile(`^(\d\d\d\d-\d\d-\d\d)`)
		if !re.MatchString(dirName) {
			continue
		}
		policyDir := filepath.Join(histPath, dirName)
		ownerPath := filepath.Join(policyDir, "/owner/", owner, "/CHANGED")

		if _, err := os.Stat(ownerPath); os.IsNotExist(err) {
			continue
		}

		policyEntry, err := getPolicyFromFile(policyDir)
		if err != nil {
			return nil, err
		}

		// If there wasn't added a new policy today, current policy
		// is available duplicate in history.
		if policyEntry["policy"] == currentPolicy {
			continue
		}

		result = append(result, policyEntry)
	}

	sort.SliceStable(result, func(i, j int) bool {
		left := result[i]["date"] + result[i]["time"] + result[i]["policy"]
		right := result[j]["date"] + result[j]["time"] + result[j]["policy"]
		return left > right
	})

	return result, nil
}
