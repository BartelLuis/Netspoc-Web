package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxParallelFortinetStatus = 4
	fortinetStatusTimeout     = 30 * time.Second
)

var fortinetStatusSemaphore = make(chan struct{}, maxParallelFortinetStatus)

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
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !hasPolicyRole(s.authorizationPolicy(), getEmailFromSession(r), "admin", "editor", "reviewer", "deployer") {
		writeError(w, "Policy operations role required", http.StatusForbidden)
		return
	}
	targets, err := s.routingFortinetTargets()
	if err != nil {
		writeError(w, "FortiGate target store is unavailable", http.StatusServiceUnavailable)
		return
	}
	statusContext, cancel := context.WithTimeout(r.Context(), fortinetStatusTimeout)
	defer cancel()
	result := make([]fortinetStatus, len(targets))
	var group sync.WaitGroup
	for index, target := range targets {
		index, target := index, target
		group.Add(1)
		go func() {
			defer group.Done()
			select {
			case fortinetStatusSemaphore <- struct{}{}:
				defer func() { <-fortinetStatusSemaphore }()
				result[index] = probeFortinetContext(statusContext, target)
			case <-statusContext.Done():
				result[index] = fortinetStatus{Name: target.Name, Type: target.Type, URL: target.URL, Scope: fortinetTargetScope(target), Error: statusContext.Err().Error()}
			}
		}()
	}
	group.Wait()
	writeRecords(w, result)
}

func probeFortinet(t FortinetTarget) fortinetStatus {
	return probeFortinetContext(context.Background(), t)
}

func probeFortinetContext(ctx context.Context, t FortinetTarget) fortinetStatus {
	status := fortinetStatus{Name: t.Name, Type: t.Type, URL: t.URL, Scope: fortinetTargetScope(t)}
	client, err := t.httpClient()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if t.Type == "fortigate" {
		err = probeFortiGate(ctx, client, t, &status)
	} else {
		err = probeFortiManager(ctx, client, t, &status)
	}
	if err != nil {
		status.Error = redactedFortinetError(t, err)
	} else {
		status.Online = true
	}
	return status
}

func fortinetTargetScope(target FortinetTarget) string {
	if target.Type == "fortimanager" {
		return target.ADOM
	}
	return target.VDOM
}

func redactedFortinetError(target FortinetTarget, err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	secrets := []string{}
	if target.Type == "fortigate" {
		if token, tokenErr := target.apiToken(); tokenErr == nil {
			secrets = append(secrets, token)
		}
	} else if target.Type == "fortimanager" {
		secrets = append(secrets, os.Getenv(target.PasswordEnv))
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "[REDACTED]")
		if escaped := url.QueryEscape(secret); escaped != secret {
			message = strings.ReplaceAll(message, escaped, "[REDACTED]")
		}
	}
	return message
}

func probeFortiGate(ctx context.Context, client *http.Client, t FortinetTarget, status *fortinetStatus) error {
	u, _ := url.Parse(strings.TrimRight(t.URL, "/") + "/api/v2/monitor/system/status")
	if t.VDOM != "" {
		q := u.Query()
		q.Set("vdom", t.VDOM)
		u.RawQuery = q.Encode()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	token, err := t.apiToken()
	if err != nil {
		return err
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

func probeFortiManager(ctx context.Context, client *http.Client, t FortinetTarget, status *fortinetStatus) error {
	endpoint := strings.TrimRight(t.URL, "/") + "/jsonrpc"
	user, password := os.Getenv(t.UsernameEnv), os.Getenv(t.PasswordEnv)
	if user == "" || password == "" {
		return fmt.Errorf("FortiManager credential environment variables are empty")
	}
	login := map[string]any{"id": 1, "method": "exec", "params": []any{map[string]any{"url": "/sys/login/user", "data": map[string]string{"user": user, "passwd": password}}}}
	var loginResult map[string]any
	if err := postRPCContext(ctx, client, endpoint, login, &loginResult); err != nil {
		return err
	}
	session := firstString(loginResult, "session")
	if session == "" {
		return fmt.Errorf("FortiManager login returned no session")
	}
	defer func() {
		logoutContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = postRPCContext(logoutContext, client, endpoint, map[string]any{"id": 3, "method": "exec", "session": session, "params": []any{map[string]string{"url": "/sys/logout"}}}, &map[string]any{})
	}()
	request := map[string]any{"id": 2, "method": "get", "session": session, "params": []any{map[string]string{"url": "/sys/status"}}}
	var result map[string]any
	if err := postRPCContext(ctx, client, endpoint, request, &result); err != nil {
		return err
	}
	status.Version = firstString(result, "Version", "version")
	status.Serial = firstString(result, "Serial Number", "serial")
	return nil
}

func postRPC(client *http.Client, endpoint string, payload any, result any) error {
	return postRPCContext(context.Background(), client, endpoint, payload, result)
}

func postRPCContext(ctx context.Context, client *http.Client, endpoint string, payload any, result any) error {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if err := doJSON(client, req, result); err != nil {
		return err
	}
	if response, ok := result.(*map[string]any); ok {
		if code, _, found := rpcStatus(*response); found && code != 0 {
			return fmt.Errorf("FortiManager returned error code %v", code)
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Fortinet endpoint returned HTTP %d", resp.StatusCode)
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
