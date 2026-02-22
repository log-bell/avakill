package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// JSONRPCReader reads JSON-RPC messages from a stream.
// Supports both newline-delimited JSON and Content-Length header framing.
type JSONRPCReader struct {
	reader *bufio.Reader
}

// NewJSONRPCReader creates a reader for the given stream.
func NewJSONRPCReader(r io.Reader) *JSONRPCReader {
	return &JSONRPCReader{reader: bufio.NewReader(r)}
}

// ReadMessage reads a single JSON-RPC message.
// Returns nil, io.EOF on end of stream.
func (r *JSONRPCReader) ReadMessage() (map[string]interface{}, error) {
	for {
		line, err := r.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(strings.TrimSpace(line)) > 0 {
				// Try to parse the last line without newline
				return r.parseLine(line)
			}
			return nil, err
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue // Skip blank lines
		}

		// Check for Content-Length header framing
		if strings.HasPrefix(trimmed, "Content-Length:") {
			return r.readContentLength(trimmed)
		}

		// Newline-delimited JSON
		return r.parseLine(trimmed)
	}
}

// readContentLength handles Content-Length header framing (LSP-style).
func (r *JSONRPCReader) readContentLength(header string) (map[string]interface{}, error) {
	parts := strings.SplitN(header, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Content-Length header: %s", header)
	}

	length, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid Content-Length value: %w", err)
	}

	// Consume remaining headers until blank line separator
	for {
		line, err := r.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Read exactly `length` bytes
	body := make([]byte, length)
	_, err = io.ReadFull(r.reader, body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("parse body: %w", err)
	}

	return msg, nil
}

// parseLine parses a single line as JSON.
func (r *JSONRPCReader) parseLine(line string) (map[string]interface{}, error) {
	trimmed := strings.TrimSpace(line)
	var msg map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &msg); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return msg, nil
}

// WriteJSONRPC writes a JSON-RPC message as newline-delimited JSON.
func WriteJSONRPC(w io.Writer, msg map[string]interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}
