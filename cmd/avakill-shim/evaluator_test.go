package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortSockPath creates a socket path short enough for macOS (104-byte limit).
func shortSockPath(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ak-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	return filepath.Join(dir, "s.sock"), func() { os.RemoveAll(dir) }
}

func TestEvaluateDaemonAllow(t *testing.T) {
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n == 0 {
			return
		}

		var req EvaluateRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			t.Errorf("unmarshal request: %v", err)
			return
		}
		if req.Tool != "read_file" {
			t.Errorf("expected tool 'read_file', got %q", req.Tool)
		}

		resp := EvaluateResponse{Decision: "allow", Policy: "default-allow"}
		data, _ := json.Marshal(resp)
		data = append(data, '\n')
		conn.Write(data)
	}()

	eval := &Evaluator{
		SocketPath: sockPath,
		Timeout:    2 * time.Second,
	}

	resp := eval.Evaluate("read_file", map[string]interface{}{"path": "/tmp/test.txt"})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %q", resp.Decision)
	}
}

func TestEvaluateDaemonDeny(t *testing.T) {
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		io.ReadAll(conn)

		resp := EvaluateResponse{
			Decision: "deny",
			Reason:   "write to /etc blocked",
			Policy:   "block-etc",
		}
		data, _ := json.Marshal(resp)
		data = append(data, '\n')
		conn.Write(data)
	}()

	eval := &Evaluator{
		SocketPath: sockPath,
		Timeout:    2 * time.Second,
	}

	resp := eval.Evaluate("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %q", resp.Decision)
	}
	if resp.Reason != "write to /etc blocked" {
		t.Errorf("unexpected reason: %q", resp.Reason)
	}
}

func TestEvaluateFailClosed(t *testing.T) {
	eval := &Evaluator{
		SocketPath: "/nonexistent/socket.sock",
	}

	resp := eval.Evaluate("write_file", map[string]interface{}{"path": "/etc/shadow"})
	if resp.Decision != "deny" {
		t.Errorf("expected deny on fail-closed, got %q", resp.Decision)
	}
	if resp.Reason == "" {
		t.Error("expected reason on fail-closed deny")
	}
}

func TestEvaluateFailClosed_NothingConfigured(t *testing.T) {
	eval := &Evaluator{}

	resp := eval.Evaluate("write_file", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected deny when nothing configured, got %q", resp.Decision)
	}
}

func TestDaemonReachable(t *testing.T) {
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	eval := &Evaluator{SocketPath: sockPath}
	if !eval.DaemonReachable() {
		t.Error("expected daemon to be reachable")
	}

	eval2 := &Evaluator{SocketPath: "/nonexistent/sock"}
	if eval2.DaemonReachable() {
		t.Error("expected daemon to be unreachable")
	}

	eval3 := &Evaluator{}
	if eval3.DaemonReachable() {
		t.Error("expected empty socket to be unreachable")
	}
}

func TestEvaluateDaemonBadResponse(t *testing.T) {
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.ReadAll(conn)
		conn.Write([]byte("not json\n"))
	}()

	eval := &Evaluator{
		SocketPath: sockPath,
		Timeout:    2 * time.Second,
	}

	resp := eval.Evaluate("write_file", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected deny on bad response, got %q", resp.Decision)
	}
}

func TestEvaluateDaemonEmptyResponse(t *testing.T) {
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.ReadAll(conn)
		// Close without sending anything
	}()

	eval := &Evaluator{
		SocketPath: sockPath,
		Timeout:    2 * time.Second,
	}

	resp := eval.Evaluate("write_file", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected deny on empty response, got %q", resp.Decision)
	}
}

func TestEvaluateCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	before, _ := os.ReadDir(tmpDir)

	eval := &Evaluator{
		SocketPath: filepath.Join(tmpDir, "nonexistent.sock"),
	}
	eval.Evaluate("test", nil)

	after, _ := os.ReadDir(tmpDir)
	if len(after) != len(before) {
		t.Error("evaluator left temp files behind")
	}
}

// --- In-process policy evaluation tests ---

func TestEvaluate_InProcessAllow(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1.0"
default_action: allow
policies:
  - name: block-writes
    tools: ["write_file"]
    action: deny
`), 0644)

	eval := &Evaluator{PolicyPath: policyPath}
	resp := eval.Evaluate("read_file", map[string]interface{}{"path": "/tmp/test.txt"})
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %q", resp.Decision)
	}
}

func TestEvaluate_InProcessDeny(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1.0"
default_action: allow
policies:
  - name: block-writes
    tools: ["write_file"]
    action: deny
    message: "writes blocked by policy"
`), 0644)

	eval := &Evaluator{PolicyPath: policyPath}
	resp := eval.Evaluate("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %q", resp.Decision)
	}
	if resp.Reason != "writes blocked by policy" {
		t.Errorf("expected custom reason, got %q", resp.Reason)
	}
	if resp.Policy != "block-writes" {
		t.Errorf("expected policy 'block-writes', got %q", resp.Policy)
	}
}

func TestEvaluate_InProcessFailClosed_BadFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`{broken yaml: [`), 0644)

	eval := &Evaluator{PolicyPath: policyPath}
	resp := eval.Evaluate("read_file", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected fail-closed deny on bad policy, got %q", resp.Decision)
	}
}

func TestEvaluate_InProcessFailClosed_MissingFile(t *testing.T) {
	eval := &Evaluator{PolicyPath: "/nonexistent/policy.yaml"}
	resp := eval.Evaluate("read_file", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected fail-closed deny on missing policy, got %q", resp.Decision)
	}
}

func TestEvaluate_InProcessPriority_OverDaemon(t *testing.T) {
	// When --policy is set, in-process evaluation should be used
	// even if --socket is also set. The daemon should NOT be contacted.
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: "1.0"
default_action: deny
policies: []
`), 0644)

	eval := &Evaluator{
		PolicyPath: policyPath,
		SocketPath: "/nonexistent/socket.sock", // would fail if contacted
	}
	resp := eval.Evaluate("test_tool", nil)
	if resp.Decision != "deny" {
		t.Errorf("expected in-process deny, got %q", resp.Decision)
	}
	// The reason should indicate default action, not daemon failure
	if resp.Reason == "no evaluation method available (fail-closed)" {
		t.Error("should have used in-process policy, not fallen through")
	}
}

func TestEvaluate_FallbackToDaemon_NoPolicySpecified(t *testing.T) {
	// When no --policy is set, should fall back to daemon socket
	sockPath, cleanup := shortSockPath(t)
	defer cleanup()

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.ReadAll(conn)
		resp := EvaluateResponse{Decision: "allow", Policy: "daemon-allow"}
		data, _ := json.Marshal(resp)
		conn.Write(data)
	}()

	eval := &Evaluator{
		SocketPath: sockPath,
		Timeout:    2 * time.Second,
	}
	resp := eval.Evaluate("read_file", nil)
	if resp.Decision != "allow" {
		t.Errorf("expected daemon allow, got %q", resp.Decision)
	}
	if resp.Policy != "daemon-allow" {
		t.Errorf("expected daemon-allow policy, got %q", resp.Policy)
	}
}
