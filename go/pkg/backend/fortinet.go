package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type fortinetStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	URL     string `json:"url"`
	Scope   string `json:"scope,omitempty"`
	Online  bool   `json:"online"`
	Version string `json:"version,omitempty"`
	Serial  string `json:"serial,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s *state) getFortinetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result := make([]fortinetStatus, 0, len(s.config.FortinetTargets))
	for _, target := range s.config.FortinetTargets {
		result = append(result, probeFortinet(target))
	}
	writeRecords(w, result)
}

func probeFortinet(t FortinetTarget) fortinetStatus {
	status := fortinetStatus{Name: t.Name, Type: t.Type, URL: t.URL, Scope: t.VDOM}
	if t.Type == "fortimanager" {
		status.Scope = t.ADOM
	}
	client, err := t.httpClient()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if t.Type == "fortigate" {
		err = probeFortiGate(client, t, &status)
	} else {
		err = probeFortiManager(client, t, &status)
	}
	if err != nil {
		status.Error = err.Error()
	} else {
		status.Online = true
	}
	return status
}

func probeFortiGate(client *http.Client, t FortinetTarget, status *fortinetStatus) error {
	u, _ := url.Parse(strings.TrimRight(t.URL, "/") + "/api/v2/monitor/system/status")
	if t.VDOM != "" {
		q := u.Query()
		q.Set("vdom", t.VDOM)
		u.RawQuery = q.Encode()
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	token := os.Getenv(t.TokenEnv)
	if token == "" {
		return fmt.Errorf("environment variable %s is empty", t.TokenEnv)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	var body map[string]any
	if err := doJSON(client, req, &body); err != nil {
		return err
	}
	status.Version = firstString(body, "version", "build")
	status.Serial = firstString(body, "serial", "serial_number")
	return nil
}

func probeFortiManager(client *http.Client, t FortinetTarget, status *fortinetStatus) error {
	endpoint := strings.TrimRight(t.URL, "/") + "/jsonrpc"
	user, password := os.Getenv(t.UsernameEnv), os.Getenv(t.PasswordEnv)
	if user == "" || password == "" {
		return fmt.Errorf("FortiManager credential environment variables are empty")
	}
	login := map[string]any{"id": 1, "method": "exec", "params": []any{map[string]any{"url": "/sys/login/user", "data": map[string]string{"user": user, "passwd": password}}}}
	var loginResult map[string]any
	if err := postRPC(client, endpoint, login, &loginResult); err != nil {
		return err
	}
	session := firstString(loginResult, "session")
	if session == "" {
		return fmt.Errorf("FortiManager login returned no session")
	}
	defer postRPC(client, endpoint, map[string]any{"id": 3, "method": "exec", "session": session, "params": []any{map[string]string{"url": "/sys/logout"}}}, &map[string]any{})
	request := map[string]any{"id": 2, "method": "get", "session": session, "params": []any{map[string]string{"url": "/sys/status"}}}
	var result map[string]any
	if err := postRPC(client, endpoint, request, &result); err != nil {
		return err
	}
	status.Version = firstString(result, "Version", "version")
	status.Serial = firstString(result, "Serial Number", "serial")
	return nil
}

func postRPC(client *http.Client, endpoint string, payload any, result any) error {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if err := doJSON(client, req, result); err != nil {
		return err
	}
	if response, ok := result.(*map[string]any); ok {
		if code, message, found := rpcStatus(*response); found && code != 0 {
			return fmt.Errorf("FortiManager error %v: %s", code, message)
		}
	}
	return nil
}

func doJSON(client *http.Client, req *http.Request, result any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func rpcStatus(value any) (float64, string, bool) {
	switch v := value.(type) {
	case map[string]any:
		if status, ok := v["status"].(map[string]any); ok {
			code, hasCode := status["code"].(float64)
			message, _ := status["message"].(string)
			return code, message, hasCode
		}
		for _, child := range v {
			if code, message, found := rpcStatus(child); found {
				return code, message, true
			}
		}
	case []any:
		for _, child := range v {
			if code, message, found := rpcStatus(child); found {
				return code, message, true
			}
		}
	}
	return 0, "", false
}

func firstString(value any, keys ...string) string {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range keys {
			if x, ok := v[key].(string); ok {
				return x
			}
		}
		for _, child := range v {
			if x := firstString(child, keys...); x != "" {
				return x
			}
		}
	case []any:
		for _, child := range v {
			if x := firstString(child, keys...); x != "" {
				return x
			}
		}
	}
	return ""
}
