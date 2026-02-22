package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// EvaluateRequest matches the daemon wire protocol (protocol.py).
type EvaluateRequest struct {
	Version int                    `json:"version"`
	Agent   string                 `json:"agent"`
	Event   string                 `json:"event"`
	Tool    string                 `json:"tool"`
	Args    map[string]interface{} `json:"args"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// EvaluateResponse matches the daemon wire protocol (protocol.py).
type EvaluateResponse struct {
	Decision  string  `json:"decision"`
	Reason    string  `json:"reason,omitempty"`
	Policy    string  `json:"policy,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
}

// Evaluator evaluates tool calls via daemon socket or subprocess fallback.
type Evaluator struct {
	SocketPath string
	PolicyPath string
	Timeout    time.Duration
	Verbose    bool
}

// Evaluate runs the fallback chain: daemon → subprocess → deny.
func (e *Evaluator) Evaluate(tool string, args map[string]interface{}) EvaluateResponse {
	// 1. Try daemon socket
	if e.SocketPath != "" {
		resp, err := e.evaluateDaemon(tool, args)
		if err == nil {
			return resp
		}
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: daemon eval failed: %v\n", err)
		}
	}

	// 2. Try subprocess fallback
	if e.PolicyPath != "" {
		resp, err := e.evaluateSubprocess(tool, args)
		if err == nil {
			return resp
		}
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: subprocess eval failed: %v\n", err)
		}
	}

	// 3. Fail-closed: deny
	return EvaluateResponse{
		Decision: "deny",
		Reason:   "all evaluation methods failed (fail-closed)",
	}
}

// evaluateDaemon connects to the daemon Unix socket, sends the request,
// shuts down the write side, reads the response. Matches client.py._send().
func (e *Evaluator) evaluateDaemon(tool string, args map[string]interface{}) (EvaluateResponse, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	socketPath := expandHome(e.SocketPath)
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	req := EvaluateRequest{
		Version: 1,
		Agent:   "mcp-shim",
		Event:   "pre_tool_use",
		Tool:    tool,
		Args:    args,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		return EvaluateResponse{}, fmt.Errorf("write: %w", err)
	}

	// Signal EOF to server (matches sock.shutdown(SHUT_WR) in client.py)
	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	// Read response
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	if len(buf) == 0 {
		return EvaluateResponse{}, fmt.Errorf("empty response from daemon")
	}

	var resp EvaluateResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return EvaluateResponse{}, fmt.Errorf("unmarshal: %w", err)
	}

	return resp, nil
}

// evaluateSubprocess spawns `avakill evaluate --json --policy <path>`,
// pipes the tool call as JSON on stdin, reads the decision from stdout.
func (e *Evaluator) evaluateSubprocess(tool string, args map[string]interface{}) (EvaluateResponse, error) {
	// Try recovered shell env first (handles launchd's restricted PATH)
	avakillBin, err := ResolveInEnv("avakill")
	if err != nil {
		// Fall back to process PATH
		avakillBin, err = exec.LookPath("avakill")
		if err != nil {
			return EvaluateResponse{}, fmt.Errorf("avakill not found in PATH: %w", err)
		}
	}

	cmd := exec.Command(avakillBin, "evaluate", "--json", "--policy", e.PolicyPath)

	// Build stdin payload matching EvaluateRequest
	req := EvaluateRequest{
		Version: 1,
		Agent:   "mcp-shim",
		Event:   "pre_tool_use",
		Tool:    tool,
		Args:    args,
	}
	stdinData, err := json.Marshal(req)
	if err != nil {
		return EvaluateResponse{}, fmt.Errorf("marshal: %w", err)
	}

	cmd.Stdin = bytes.NewReader(stdinData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	// Try to parse JSON from stdout regardless of exit code.
	// avakill evaluate --json writes the response to stdout even on deny (exit 2).
	if stdout.Len() > 0 {
		var resp EvaluateResponse
		if jsonErr := json.Unmarshal(stdout.Bytes(), &resp); jsonErr == nil {
			return resp, nil
		}
	}

	if err != nil {
		// Exit code 2 = deny, but we couldn't parse JSON above
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			return EvaluateResponse{
				Decision: "deny",
				Reason:   "denied by subprocess (no structured output)",
			}, nil
		}
		return EvaluateResponse{}, fmt.Errorf("subprocess: %w", err)
	}

	// If we got here, cmd.Run() succeeded but stdout had no valid JSON
	return EvaluateResponse{}, fmt.Errorf("no valid JSON in subprocess output")
}

// DaemonReachable checks if the daemon socket is connectable.
func (e *Evaluator) DaemonReachable() bool {
	if e.SocketPath == "" {
		return false
	}
	socketPath := expandHome(e.SocketPath)
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

