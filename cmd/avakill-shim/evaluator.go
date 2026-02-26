package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
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

// Evaluator evaluates tool calls via in-process policy, daemon socket, or fail-closed deny.
type Evaluator struct {
	SocketPath  string
	PolicyPath  string
	Timeout     time.Duration
	Verbose     bool
	KillSwitch  *KillSwitch
	policyCache *PolicyCache
	cacheOnce   sync.Once
}

// Evaluate runs the evaluation chain: kill switch → in-process → daemon → deny.
func (e *Evaluator) Evaluate(tool string, args map[string]interface{}) EvaluateResponse {
	// 0. Kill switch — instant deny, before all policy evaluation
	if e.KillSwitch != nil {
		if engaged, reason := e.KillSwitch.IsEngaged(); engaged {
			return EvaluateResponse{
				Decision: "deny",
				Reason:   fmt.Sprintf("KILL SWITCH ENGAGED: %s", reason),
			}
		}
	}

	// 1. In-process policy evaluation (if --policy set)
	if e.PolicyPath != "" {
		e.cacheOnce.Do(func() {
			e.policyCache = NewPolicyCache(e.PolicyPath, e.Verbose)
		})
		resp, err := e.policyCache.Evaluate(tool, args)
		if err == nil {
			return resp
		}
		// If --policy is set but broken, fail-closed (do NOT fall through to daemon)
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: in-process policy eval failed: %v\n", err)
		}
		return EvaluateResponse{
			Decision: "deny",
			Reason:   fmt.Sprintf("policy file error (fail-closed): %v", err),
		}
	}

	// 2. Daemon socket fallback (if --socket set, no --policy)
	if e.SocketPath != "" {
		resp, err := e.evaluateDaemon(tool, args)
		if err == nil {
			return resp
		}
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: daemon eval failed: %v\n", err)
		}
	}

	// 3. Fail-closed: deny
	return EvaluateResponse{
		Decision: "deny",
		Reason:   "no evaluation method available (fail-closed)",
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
