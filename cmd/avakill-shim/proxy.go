package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Proxy relays JSON-RPC messages bidirectionally between client (stdin/stdout)
// and an upstream MCP server, intercepting tools/call for policy evaluation.
type Proxy struct {
	Evaluator      *Evaluator
	Verbose        bool
	clientWriteMu  sync.Mutex // protects concurrent writes to clientOut
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

	// Upstream → Client (passthrough)
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

		// Allowed or non-tools/call — forward to upstream
		if err := WriteJSONRPC(upstreamOut, msg); err != nil {
			return err
		}
	}
}

// relayUpstreamToClient reads from upstream and forwards to client.
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

		if err := p.writeToClient(clientOut, msg); err != nil {
			return err
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
					"text": fmt.Sprintf("\u26d4 AvaKill blocked this tool call: %s. Policy: %s", reason, policy),
				},
			},
			"isError": true,
		},
	}
}
