package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReadNewlineDelimited(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"tools/call","id":1}` + "\n"
	reader := NewJSONRPCReader(strings.NewReader(input))

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg["method"] != "tools/call" {
		t.Errorf("expected method tools/call, got %v", msg["method"])
	}

	// ID should be float64 from JSON
	if msg["id"] != float64(1) {
		t.Errorf("expected id 1, got %v", msg["id"])
	}
}

func TestReadContentLength(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"initialize","id":1}`
	input := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)

	reader := NewJSONRPCReader(strings.NewReader(input))
	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg["method"] != "initialize" {
		t.Errorf("expected method initialize, got %v", msg["method"])
	}
}

func TestReadContentLengthMultipleHeaders(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"test","id":2}`
	input := fmt.Sprintf("Content-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(body), body)

	reader := NewJSONRPCReader(strings.NewReader(input))
	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if msg["method"] != "test" {
		t.Errorf("expected method test, got %v", msg["method"])
	}
}

func TestReadEOF(t *testing.T) {
	reader := NewJSONRPCReader(strings.NewReader(""))
	msg, err := reader.ReadMessage()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
	if msg != nil {
		t.Errorf("expected nil message on EOF, got %v", msg)
	}
}

func TestReadInvalidJSON(t *testing.T) {
	reader := NewJSONRPCReader(strings.NewReader("not json\n"))
	_, err := reader.ReadMessage()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestReadMultipleMessages(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"a","id":1}` + "\n" +
		`{"jsonrpc":"2.0","method":"b","id":2}` + "\n" +
		`{"jsonrpc":"2.0","method":"c","id":3}` + "\n"

	reader := NewJSONRPCReader(strings.NewReader(input))

	methods := []string{}
	for {
		msg, err := reader.ReadMessage()
		if err != nil {
			break
		}
		methods = append(methods, msg["method"].(string))
	}

	if len(methods) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(methods))
	}
	if methods[0] != "a" || methods[1] != "b" || methods[2] != "c" {
		t.Errorf("unexpected methods: %v", methods)
	}
}

func TestReadSkipBlankLines(t *testing.T) {
	input := "\n\n" + `{"jsonrpc":"2.0","method":"test","id":1}` + "\n\n"
	reader := NewJSONRPCReader(strings.NewReader(input))

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg["method"] != "test" {
		t.Errorf("expected method test, got %v", msg["method"])
	}
}

func TestReadLastLineWithoutNewline(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"test","id":1}`
	reader := NewJSONRPCReader(strings.NewReader(input))

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg["method"] != "test" {
		t.Errorf("expected method test, got %v", msg["method"])
	}
}

func TestWriteJSONRPC(t *testing.T) {
	var buf bytes.Buffer
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      float64(1),
		"result":  map[string]interface{}{"content": []interface{}{}},
	}

	err := WriteJSONRPC(&buf, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.HasSuffix(output, "\n") {
		t.Error("expected trailing newline")
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %v", parsed["jsonrpc"])
	}
}

func TestWriteJSONRPCRoundTrip(t *testing.T) {
	// Write then read
	var buf bytes.Buffer
	original := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"id":      float64(42),
		"params": map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/tmp/test"},
		},
	}

	if err := WriteJSONRPC(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := NewJSONRPCReader(&buf)
	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if msg["method"] != "tools/call" {
		t.Errorf("round-trip method mismatch: %v", msg["method"])
	}
	if msg["id"] != float64(42) {
		t.Errorf("round-trip id mismatch: %v", msg["id"])
	}
}
