package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// Proxy relays JSON-RPC messages bidirectionally between client (stdin/stdout)
// and an upstream MCP server, intercepting tools/call for policy evaluation.
type Proxy struct {
	Evaluator     *Evaluator
	Verbose       bool
	clientWriteMu sync.Mutex // protects concurrent writes to clientOut

	// Tool hash detection
	ToolHasher    *ToolHasher     // nil = disabled
	ToolHashCfg   *ToolHashConfig // nil = disabled
	ServerCommand string
	PinToolsMode  bool
	PinToolsDone  chan struct{} // closed after first tools/list pinned in pin-tools mode

	// Request tracking: maps stringified JSON-RPC IDs to method names
	pendingMu       sync.Mutex
	pendingRequests map[string]string // stringified id → method

	// Block state: when set, handleToolsCall denies ALL tools/call
	toolsBlocked atomic.Bool
}

// Run starts the bidirectional relay.
// clientIn/clientOut = our stdin/stdout (MCP client side)
// upstreamIn/upstreamOut = upstream process stdout/stdin
// When upstreamOut implements io.Closer (e.g. os/exec StdinPipe), it will
// be closed when the client disconnects so the upstream process can exit.
func (p *Proxy) Run(clientIn io.Reader, clientOut io.Writer, upstreamIn io.Reader, upstreamOut io.Writer) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Client → Upstream (with interception)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := p.relayClientToUpstream(clientIn, upstreamOut, clientOut)
		// Close upstream stdin so the upstream process sees EOF and exits
		if c, ok := upstreamOut.(io.Closer); ok {
			c.Close()
		}
		if err != nil {
			errCh <- fmt.Errorf("client→upstream: %w", err)
		}
	}()

	// Upstream → Client (with tools/list interception)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.relayUpstreamToClient(upstreamIn, clientOut); err != nil {
			errCh <- fmt.Errorf("upstream→client: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	// Return first error, if any
	for err := range errCh {
		return err
	}
	return nil
}

// writeToClient writes a message to the client output with mutex protection.
func (p *Proxy) writeToClient(clientOut io.Writer, msg map[string]interface{}) error {
	p.clientWriteMu.Lock()
	defer p.clientWriteMu.Unlock()
	return WriteJSONRPC(clientOut, msg)
}

// trackRequest records a request ID and its method for response matching.
func (p *Proxy) trackRequest(id interface{}, method string) {
	if p.pendingRequests == nil {
		return
	}
	key := stringifyID(id)
	p.pendingMu.Lock()
	p.pendingRequests[key] = method
	p.pendingMu.Unlock()
}

// popRequest retrieves and removes a tracked request method by response ID.
func (p *Proxy) popRequest(id interface{}) (string, bool) {
	if p.pendingRequests == nil {
		return "", false
	}
	key := stringifyID(id)
	p.pendingMu.Lock()
	method, ok := p.pendingRequests[key]
	if ok {
		delete(p.pendingRequests, key)
	}
	p.pendingMu.Unlock()
	return method, ok
}

// relayClientToUpstream reads from client, intercepts tools/call, forwards rest.
func (p *Proxy) relayClientToUpstream(clientIn io.Reader, upstreamOut io.Writer, clientOut io.Writer) error {
	reader := NewJSONRPCReader(clientIn)

	for {
		msg, err := reader.ReadMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		response := p.handleToolsCall(msg)
		if response != nil {
			// Denied — send response directly to client
			if err := p.writeToClient(clientOut, response); err != nil {
				if p.Verbose {
					fmt.Fprintf(os.Stderr, "avakill-shim: failed to write deny response: %v\n", err)
				}
			}
			continue
		}

		// Track tools/list requests for response interception
		if method, _ := msg["method"].(string); method == "tools/list" {
			p.trackRequest(msg["id"], method)
		}

		// Allowed or non-tools/call — forward to upstream
		if err := WriteJSONRPC(upstreamOut, msg); err != nil {
			return err
		}
	}
}

// relayUpstreamToClient reads from upstream and forwards to client.
// Intercepts tools/list responses for tool hash comparison.
func (p *Proxy) relayUpstreamToClient(upstreamIn io.Reader, clientOut io.Writer) error {
	reader := NewJSONRPCReader(upstreamIn)

	for {
		msg, err := reader.ReadMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Check if this is a response to a tracked tools/list request
		if id, hasID := msg["id"]; hasID {
			if method, tracked := p.popRequest(id); tracked && method == "tools/list" {
				p.handleToolsListResponse(msg, clientOut)
				// Always forward the response to the client
				if err := p.writeToClient(clientOut, msg); err != nil {
					return err
				}
				continue
			}
		}

		if err := p.writeToClient(clientOut, msg); err != nil {
			return err
		}
	}
}

// handleToolsListResponse processes a tools/list response for rug-pull detection.
func (p *Proxy) handleToolsListResponse(msg map[string]interface{}, clientOut io.Writer) {
	if p.ToolHasher == nil || p.ToolHashCfg == nil {
		return
	}

	tools, err := parseToolsList(msg)
	if err != nil {
		if p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: failed to parse tools/list: %v\n", err)
		}
		return
	}

	changes, manifest, err := p.ToolHasher.ProcessToolsList(p.ServerCommand, tools)
	if err != nil {
		fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: process error: %v\n", err)
		return
	}

	mPath := manifestPath(p.ToolHasher.ManifestDir, p.ServerCommand)

	if changes == nil {
		// First encounter — save manifest
		if p.ToolHashCfg.PinOnFirstSeen {
			if err := saveManifest(mPath, manifest); err != nil {
				fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: failed to save manifest: %v\n", err)
			} else if p.Verbose {
				fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: pinned %d tools for %q\n", len(manifest.Tools), p.ServerCommand)
			}
		}
		// Signal pin-tools mode completion
		if p.PinToolsMode && p.PinToolsDone != nil {
			select {
			case <-p.PinToolsDone:
			default:
				close(p.PinToolsDone)
			}
		}
		return
	}

	if len(changes) == 0 {
		if p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: no changes detected\n")
		}
		// Signal pin-tools mode completion (no changes = success)
		if p.PinToolsMode && p.PinToolsDone != nil {
			select {
			case <-p.PinToolsDone:
			default:
				close(p.PinToolsDone)
			}
		}
		return
	}

	// Changes detected — take action
	for _, ch := range changes {
		fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: ⚠ tool %s %s", ch.Name, ch.Type)
		if ch.OldHash != "" {
			fmt.Fprintf(os.Stderr, " (was %s…)", ch.OldHash[:12])
		}
		if ch.NewHash != "" {
			fmt.Fprintf(os.Stderr, " (now %s…)", ch.NewHash[:12])
		}
		fmt.Fprintln(os.Stderr)
	}

	switch p.ToolHashCfg.Action {
	case "log":
		// Already logged above
	case "warn":
		// Inject a warning notification to the client
		warning := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/message",
			"params": map[string]interface{}{
				"level":   "warning",
				"message": fmt.Sprintf("AvaKill: %d tool definition(s) changed since last seen — possible rug pull", len(changes)),
			},
		}
		if err := p.writeToClient(clientOut, warning); err != nil && p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: failed to send warning: %v\n", err)
		}
	case "block":
		p.toolsBlocked.Store(true)
		fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: BLOCKING all tools/call — rug pull detected\n")
		// Inject error notification
		warning := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "notifications/message",
			"params": map[string]interface{}{
				"level":   "error",
				"message": fmt.Sprintf("AvaKill: %d tool definition(s) changed — ALL tool calls blocked", len(changes)),
			},
		}
		if err := p.writeToClient(clientOut, warning); err != nil && p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: failed to send block notification: %v\n", err)
		}
	}

	// Update manifest if action is log or warn (not block — keep old manifest for evidence)
	if p.ToolHashCfg.Action != "block" {
		if err := saveManifest(mPath, manifest); err != nil {
			fmt.Fprintf(os.Stderr, "avakill-shim: tool-hash: failed to update manifest: %v\n", err)
		}
	}
}

// handleToolsCall intercepts tools/call requests and evaluates them.
// Returns a deny response map if blocked, or nil to forward.
func (p *Proxy) handleToolsCall(msg map[string]interface{}) map[string]interface{} {
	method, _ := msg["method"].(string)
	if method != "tools/call" {
		return nil
	}

	params, _ := msg["params"].(map[string]interface{})
	if params == nil {
		return nil
	}

	toolName, _ := params["name"].(string)
	arguments, _ := params["arguments"].(map[string]interface{})
	if arguments == nil {
		arguments = make(map[string]interface{})
	}
	requestID := msg["id"]

	// Check rug-pull block state first
	if p.toolsBlocked.Load() {
		if p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: blocked (rug pull): %s\n", toolName)
		}
		return map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      requestID,
			"result": map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{
						"type": "text",
						"text": fmt.Sprintf("⛔ AvaKill blocked this tool call: tool definitions changed since initial registration (possible rug pull). Tool: %s", toolName),
					},
				},
				"isError": true,
			},
		}
	}

	if p.Verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: intercepted tools/call: %s\n", toolName)
	}

	resp := p.Evaluator.Evaluate(toolName, arguments)

	if resp.Decision == "allow" {
		if p.Verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: allowed: %s (policy: %s)\n", toolName, resp.Policy)
		}
		return nil
	}

	// Denied — build MCP error response matching proxy.py:289-304
	reason := resp.Reason
	if reason == "" {
		reason = "Denied by policy"
	}
	policy := resp.Policy
	if policy == "" {
		policy = "unknown"
	}

	if p.Verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: denied: %s — %s (policy: %s)\n", toolName, reason, policy)
	}

	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID,
		"result": map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": fmt.Sprintf("⛔ AvaKill blocked this tool call: %s. Policy: %s", reason, policy),
				},
			},
			"isError": true,
		},
	}
}
