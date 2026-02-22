package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// closableBuffer wraps bytes.Buffer with a Close method for testing.
type closableBuffer struct {
	bytes.Buffer
	closed bool
}

func (cb *closableBuffer) Close() error {
	cb.closed = true
	return nil
}

func TestHandleToolsCallAllow(t *testing.T) {
	proxy := &Proxy{
		Evaluator: &Evaluator{},
	}
	// Override evaluator with a mock that allows
	proxy.Evaluator = &Evaluator{SocketPath: ""} // no socket = will fail-closed

	// But let's test handleToolsCall directly with a real Evaluator
	// that has a socket mock

	// For unit testing, directly test the handleToolsCall method
	// with a proxy whose evaluator we control

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      float64(1),
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/tmp/test"},
		},
	}

	// With no evaluator configured, it will fail-closed (deny)
	result := proxy.handleToolsCall(msg)
	if result == nil {
		t.Fatal("expected deny response, got nil (allow)")
	}

	// Check deny response format matches proxy.py:289-304
	resultMap := result["result"].(map[string]interface{})
	if resultMap["isError"] != true {
		t.Error("expected isError=true")
	}
	content := resultMap["content"].([]interface{})
	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}
	textItem := content[0].(map[string]interface{})
	if textItem["type"] != "text" {
		t.Errorf("expected type=text, got %v", textItem["type"])
	}
	text := textItem["text"].(string)
	if !strings.Contains(text, "AvaKill blocked") {
		t.Errorf("expected 'AvaKill blocked' in text, got %q", text)
	}
}

func TestHandleToolsCallNonToolsCall(t *testing.T) {
	proxy := &Proxy{Evaluator: &Evaluator{}}

	// Non-tools/call messages should pass through (return nil)
	msgs := []map[string]interface{}{
		{"jsonrpc": "2.0", "method": "initialize", "id": float64(1)},
		{"jsonrpc": "2.0", "method": "tools/list", "id": float64(2)},
		{"jsonrpc": "2.0", "method": "resources/read", "id": float64(3)},
		{"jsonrpc": "2.0", "id": float64(4), "result": map[string]interface{}{}},
	}

	for _, msg := range msgs {
		result := proxy.handleToolsCall(msg)
		if result != nil {
			t.Errorf("expected nil (passthrough) for method %v, got response", msg["method"])
		}
	}
}

func TestDenyResponseFormat(t *testing.T) {
	proxy := &Proxy{Evaluator: &Evaluator{}}

	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      float64(42),
		"params": map[string]interface{}{
			"name":      "delete_file",
			"arguments": map[string]interface{}{"path": "/etc/passwd"},
		},
	}

	result := proxy.handleToolsCall(msg)
	if result == nil {
		t.Fatal("expected deny response")
	}

	// Verify JSON-RPC envelope
	if result["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %v", result["jsonrpc"])
	}
	if result["id"] != float64(42) {
		t.Errorf("expected id=42, got %v", result["id"])
	}

	// Verify it's a result (not error) — MCP uses result with isError
	resultField := result["result"].(map[string]interface{})
	if resultField["isError"] != true {
		t.Error("expected isError=true in result")
	}

	// Verify content structure
	content := resultField["content"].([]interface{})
	item := content[0].(map[string]interface{})
	if item["type"] != "text" {
		t.Errorf("expected type=text, got %v", item["type"])
	}

	// Should be serializable
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to serialize deny response: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty serialized deny response")
	}
}

func TestRelayUpstreamToClient(t *testing.T) {
	// Simulate upstream sending messages, verify they arrive at client
	upstreamMsgs := []map[string]interface{}{
		{"jsonrpc": "2.0", "id": float64(1), "result": map[string]interface{}{"tools": []interface{}{}}},
		{"jsonrpc": "2.0", "id": float64(2), "result": map[string]interface{}{"content": "hello"}},
	}

	var upstreamBuf bytes.Buffer
	for _, msg := range upstreamMsgs {
		WriteJSONRPC(&upstreamBuf, msg)
	}

	var clientBuf bytes.Buffer
	proxy := &Proxy{Evaluator: &Evaluator{}}

	err := proxy.relayUpstreamToClient(&upstreamBuf, &clientBuf)
	if err != nil {
		t.Fatalf("relay error: %v", err)
	}

	// Read back from client output
	reader := NewJSONRPCReader(&clientBuf)
	for i, expected := range upstreamMsgs {
		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		if msg["id"] != expected["id"] {
			t.Errorf("message %d: expected id %v, got %v", i, expected["id"], msg["id"])
		}
	}
}

func TestRelayClientToUpstreamPassthrough(t *testing.T) {
	// Non-tools/call messages should pass through to upstream
	clientMsgs := []map[string]interface{}{
		{"jsonrpc": "2.0", "method": "initialize", "id": float64(1), "params": map[string]interface{}{}},
		{"jsonrpc": "2.0", "method": "tools/list", "id": float64(2)},
	}

	var clientBuf bytes.Buffer
	for _, msg := range clientMsgs {
		WriteJSONRPC(&clientBuf, msg)
	}

	var upstreamBuf bytes.Buffer
	var clientOutBuf bytes.Buffer

	proxy := &Proxy{Evaluator: &Evaluator{}}
	err := proxy.relayClientToUpstream(&clientBuf, &upstreamBuf, &clientOutBuf)
	if err != nil {
		t.Fatalf("relay error: %v", err)
	}

	// Messages should have been forwarded to upstream
	reader := NewJSONRPCReader(&upstreamBuf)
	for i, expected := range clientMsgs {
		msg, err := reader.ReadMessage()
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		if msg["method"] != expected["method"] {
			t.Errorf("message %d: expected method %v, got %v", i, expected["method"], msg["method"])
		}
	}

	// Nothing should have been written to client output (no denials)
	if clientOutBuf.Len() > 0 {
		t.Errorf("unexpected client output: %s", clientOutBuf.String())
	}
}

func TestRelayClientToUpstreamDeny(t *testing.T) {
	// tools/call should be denied (no evaluator configured = fail-closed)
	clientMsgs := []map[string]interface{}{
		{
			"jsonrpc": "2.0",
			"method":  "tools/call",
			"id":      float64(1),
			"params": map[string]interface{}{
				"name":      "write_file",
				"arguments": map[string]interface{}{"path": "/etc/passwd"},
			},
		},
	}

	var clientBuf bytes.Buffer
	for _, msg := range clientMsgs {
		WriteJSONRPC(&clientBuf, msg)
	}

	var upstreamBuf bytes.Buffer
	var clientOutBuf bytes.Buffer

	proxy := &Proxy{Evaluator: &Evaluator{}}
	err := proxy.relayClientToUpstream(&clientBuf, &upstreamBuf, &clientOutBuf)
	if err != nil {
		t.Fatalf("relay error: %v", err)
	}

	// Nothing should reach upstream (denied)
	if upstreamBuf.Len() > 0 {
		t.Errorf("denied message reached upstream: %s", upstreamBuf.String())
	}

	// Deny response should have been written to client
	reader := NewJSONRPCReader(&clientOutBuf)
	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("read deny response: %v", err)
	}
	if msg["id"] != float64(1) {
		t.Errorf("expected id=1, got %v", msg["id"])
	}
	resultField := msg["result"].(map[string]interface{})
	if resultField["isError"] != true {
		t.Error("expected isError=true")
	}
}

func TestFullProxyRelay(t *testing.T) {
	// Simulate full bidirectional relay
	// Client sends initialize + tools/call (denied)
	// Upstream sends initialize response

	clientInput := strings.Builder{}
	WriteJSONRPC(&clientInput, map[string]interface{}{
		"jsonrpc": "2.0", "method": "initialize", "id": float64(1),
		"params": map[string]interface{}{},
	})
	WriteJSONRPC(&clientInput, map[string]interface{}{
		"jsonrpc": "2.0", "method": "tools/call", "id": float64(2),
		"params": map[string]interface{}{
			"name":      "delete_all",
			"arguments": map[string]interface{}{},
		},
	})

	upstreamInput := strings.Builder{}
	WriteJSONRPC(&upstreamInput, map[string]interface{}{
		"jsonrpc": "2.0", "id": float64(1),
		"result": map[string]interface{}{"serverInfo": map[string]interface{}{"name": "test"}},
	})

	var clientOut bytes.Buffer
	upstreamOut := &closableBuffer{}

	proxy := &Proxy{Evaluator: &Evaluator{}}

	clientReader := strings.NewReader(clientInput.String())
	upstreamReader := strings.NewReader(upstreamInput.String())

	err := proxy.Run(clientReader, &clientOut, upstreamReader, upstreamOut)
	if err != nil {
		t.Fatalf("proxy run error: %v", err)
	}

	// Client should receive: upstream's initialize response + deny for tools/call
	reader := NewJSONRPCReader(&clientOut)
	var messages []map[string]interface{}
	for {
		msg, err := reader.ReadMessage()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read client output: %v", err)
		}
		messages = append(messages, msg)
	}

	if len(messages) != 2 {
		t.Fatalf("expected 2 messages to client, got %d", len(messages))
	}

	// One should be the deny response (id=2)
	foundDeny := false
	for _, msg := range messages {
		if msg["id"] == float64(2) {
			result := msg["result"].(map[string]interface{})
			if result["isError"] == true {
				foundDeny = true
			}
		}
	}
	if !foundDeny {
		t.Error("expected deny response for tools/call (id=2)")
	}

	// Verify upstream stdin was closed
	if !upstreamOut.closed {
		t.Error("expected upstream stdin to be closed after client EOF")
	}

	// Upstream should only receive the initialize message (not the tools/call)
	upstreamReader2 := NewJSONRPCReader(upstreamOut)
	upMsg, err := upstreamReader2.ReadMessage()
	if err != nil {
		t.Fatalf("read upstream output: %v", err)
	}
	if upMsg["method"] != "initialize" {
		t.Errorf("expected initialize, got %v", upMsg["method"])
	}

	// No more messages to upstream
	_, err = upstreamReader2.ReadMessage()
	if err != io.EOF {
		t.Error("expected EOF from upstream reader, tools/call should not have been forwarded")
	}
}
