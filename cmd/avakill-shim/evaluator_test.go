package main

import (
	"encoding/json"
	"fmt"
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

func TestEvaluateDaemonUnreachableFallsThrough(t *testing.T) {
	eval := &Evaluator{
		SocketPath: "/nonexistent/socket.sock",
		PolicyPath: "/nonexistent/policy.yaml",
		Verbose:    true,
	}

	resp := eval.Evaluate("write_file", map[string]interface{}{"path": "/etc/shadow"})
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %q", resp.Decision)
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

// fakeAvakill creates a shell script named "avakill" in a temp dir that
// writes the given stdout string and exits with the given code.
// It returns the temp dir (caller must defer os.RemoveAll) and sets PATH
// so ResolveInEnv / exec.LookPath will find the fake.
func fakeAvakill(t *testing.T, stdout string, exitCode int) (cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "avakill")

	content := "#!/bin/sh\n"
	if stdout != "" {
		content += "printf '%s' '" + stdout + "'\n"
	}
	content += "exit " + fmt.Sprintf("%d", exitCode) + "\n"

	if err := os.WriteFile(script, []byte(content), 0755); err != nil {
		t.Fatalf("write fake avakill: %v", err)
	}

	origPath := os.Getenv("PATH")
	newPath := dir + ":" + origPath
	os.Setenv("PATH", newPath)

	// Seed the env cache so ResolveInEnv finds our fake binary first,
	// bypassing the shell recovery (which spawns a new shell that won't
	// have our modified PATH).
	ResetEnvCache()
	envOnce.Do(func() {
		envCache = map[string]string{"PATH": newPath}
		envErr = nil
	})

	return func() {
		os.Setenv("PATH", origPath)
		ResetEnvCache()
	}
}

func TestEvaluateSubprocessDenyWithJSON(t *testing.T) {
	// Fake avakill outputs JSON deny on stdout and exits 2
	denyResp := `{"decision":"deny","reason":"write to /etc blocked by policy","policy":"block-etc"}`
	cleanup := fakeAvakill(t, denyResp, 2)
	defer cleanup()

	eval := &Evaluator{PolicyPath: "/tmp/fake-policy.yaml"}
	resp, err := eval.evaluateSubprocess("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %q", resp.Decision)
	}
	if resp.Reason != "write to /etc blocked by policy" {
		t.Errorf("expected real deny reason, got %q", resp.Reason)
	}
	if resp.Policy != "block-etc" {
		t.Errorf("expected policy 'block-etc', got %q", resp.Policy)
	}
}

func TestEvaluateSubprocessDenyNoJSON(t *testing.T) {
	// Fake avakill exits 2 with no stdout — should get fallback reason
	cleanup := fakeAvakill(t, "", 2)
	defer cleanup()

	eval := &Evaluator{PolicyPath: "/tmp/fake-policy.yaml"}
	resp, err := eval.evaluateSubprocess("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny, got %q", resp.Decision)
	}
	if resp.Reason != "denied by subprocess (no structured output)" {
		t.Errorf("expected fallback reason, got %q", resp.Reason)
	}
}

func TestEvaluateSubprocessAllow(t *testing.T) {
	// Fake avakill outputs JSON allow on stdout and exits 0
	allowResp := `{"decision":"allow","policy":"default-allow"}`
	cleanup := fakeAvakill(t, allowResp, 0)
	defer cleanup()

	eval := &Evaluator{PolicyPath: "/tmp/fake-policy.yaml"}
	resp, err := eval.evaluateSubprocess("read_file", map[string]interface{}{"path": "/tmp/test.txt"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow, got %q", resp.Decision)
	}
	if resp.Policy != "default-allow" {
		t.Errorf("expected policy 'default-allow', got %q", resp.Policy)
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
