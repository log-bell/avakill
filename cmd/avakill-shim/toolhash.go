package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ToolDefinition represents a single tool from a tools/list response.
type ToolDefinition struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolEntry is a stored hash for a single tool in a manifest.
type ToolEntry struct {
	Hash    string `json:"hash"`
	FirstAt string `json:"first_seen_at"`
}

// ToolManifest is the persisted set of tool hashes for one MCP server.
type ToolManifest struct {
	ServerCommand string               `json:"server_command"`
	CreatedAt     string               `json:"created_at"`
	UpdatedAt     string               `json:"updated_at"`
	Tools         map[string]ToolEntry `json:"tools"`
}

// ToolChange describes a detected change in a tool definition.
type ToolChange struct {
	Name    string `json:"name"`
	Type    string `json:"type"` // "modified", "added", "removed"
	OldHash string `json:"old_hash,omitempty"`
	NewHash string `json:"new_hash,omitempty"`
}

// ToolHasher compares tool definitions against stored manifests.
type ToolHasher struct {
	ManifestDir string
	Verbose     bool
}

// NewToolHasher creates a ToolHasher with the given manifest directory.
func NewToolHasher(manifestDir string, verbose bool) *ToolHasher {
	return &ToolHasher{
		ManifestDir: manifestDir,
		Verbose:     verbose,
	}
}

// canonicalJSON produces deterministic JSON by recursively sorting map keys.
// Go's json.Marshal does NOT sort arbitrary map[string]interface{} keys,
// so inputSchema (arbitrary JSON) needs recursive sorting.
func canonicalJSON(v interface{}) ([]byte, error) {
	sorted := sortValue(v)
	return json.Marshal(sorted)
}

// sortValue recursively sorts map keys and returns a structure that
// json.Marshal will serialize deterministically.
func sortValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Use json.RawMessage pairs to preserve order
		pairs := make([]sortedMapEntry, len(keys))
		for i, k := range keys {
			pairs[i] = sortedMapEntry{Key: k, Value: sortValue(val[k])}
		}
		return sortedMap(pairs)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sortValue(item)
		}
		return result
	default:
		return v
	}
}

// sortedMapEntry is a key-value pair for ordered serialization.
type sortedMapEntry struct {
	Key   string
	Value interface{}
}

// sortedMap is a slice of key-value pairs that serializes as a JSON object
// with keys in the order they appear in the slice.
type sortedMap []sortedMapEntry

func (sm sortedMap) MarshalJSON() ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('{')
	for i, entry := range sm {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(entry.Key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		valJSON, err := json.Marshal(entry.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(valJSON)
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// hashToolDefinition computes a SHA-256 hex digest of a tool's canonical form.
func hashToolDefinition(tool ToolDefinition) (string, error) {
	obj := map[string]interface{}{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": tool.InputSchema,
	}
	data, err := canonicalJSON(obj)
	if err != nil {
		return "", fmt.Errorf("canonical JSON: %w", err)
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h), nil
}

// manifestPath returns the file path for a server's manifest.
// Uses SHA-256 of the server command, truncated to 16 hex chars.
func manifestPath(manifestDir, serverCommand string) string {
	h := sha256.Sum256([]byte(serverCommand))
	name := fmt.Sprintf("%x", h)[:16]
	return filepath.Join(manifestDir, name+".json")
}

// loadManifest reads a manifest from disk.
// Returns os.ErrNotExist transparently for first-encounter detection.
func loadManifest(path string) (*ToolManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m ToolManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// saveManifest writes a manifest to disk, creating directories as needed.
func saveManifest(path string, manifest *ToolManifest) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// ProcessToolsList compares incoming tools against the stored manifest.
// Returns changes and the updated manifest. Does NOT save — caller decides.
func (th *ToolHasher) ProcessToolsList(serverCmd string, tools []ToolDefinition) ([]ToolChange, *ToolManifest, error) {
	mPath := manifestPath(th.ManifestDir, serverCmd)
	existing, err := loadManifest(mPath)

	now := time.Now().UTC().Format(time.RFC3339)

	if err != nil {
		// First encounter — build new manifest, no changes to report
		if os.IsNotExist(err) {
			manifest := &ToolManifest{
				ServerCommand: serverCmd,
				CreatedAt:     now,
				UpdatedAt:     now,
				Tools:         make(map[string]ToolEntry),
			}
			for _, tool := range tools {
				hash, herr := hashToolDefinition(tool)
				if herr != nil {
					return nil, nil, herr
				}
				manifest.Tools[tool.Name] = ToolEntry{Hash: hash, FirstAt: now}
			}
			return nil, manifest, nil
		}
		return nil, nil, fmt.Errorf("load manifest: %w", err)
	}

	// Compare against existing manifest
	var changes []ToolChange
	newTools := make(map[string]ToolEntry)
	seen := make(map[string]bool)

	for _, tool := range tools {
		hash, herr := hashToolDefinition(tool)
		if herr != nil {
			return nil, nil, herr
		}
		seen[tool.Name] = true

		if entry, ok := existing.Tools[tool.Name]; ok {
			if entry.Hash != hash {
				changes = append(changes, ToolChange{
					Name:    tool.Name,
					Type:    "modified",
					OldHash: entry.Hash,
					NewHash: hash,
				})
				newTools[tool.Name] = ToolEntry{Hash: hash, FirstAt: entry.FirstAt}
			} else {
				newTools[tool.Name] = entry
			}
		} else {
			changes = append(changes, ToolChange{
				Name:    tool.Name,
				Type:    "added",
				NewHash: hash,
			})
			newTools[tool.Name] = ToolEntry{Hash: hash, FirstAt: now}
		}
	}

	// Detect removed tools
	for name, entry := range existing.Tools {
		if !seen[name] {
			changes = append(changes, ToolChange{
				Name:    name,
				Type:    "removed",
				OldHash: entry.Hash,
			})
		}
	}

	manifest := &ToolManifest{
		ServerCommand: existing.ServerCommand,
		CreatedAt:     existing.CreatedAt,
		UpdatedAt:     now,
		Tools:         newTools,
	}

	return changes, manifest, nil
}

// parseToolsList extracts tool definitions from a JSON-RPC tools/list response.
func parseToolsList(msg map[string]interface{}) ([]ToolDefinition, error) {
	result, ok := msg["result"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'result' field")
	}

	toolsRaw, ok := result["tools"]
	if !ok {
		return nil, fmt.Errorf("missing 'tools' field in result")
	}

	toolsList, ok := toolsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'tools' is not an array")
	}

	var tools []ToolDefinition
	for i, item := range toolsList {
		toolMap, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("tool[%d] is not an object", i)
		}

		name, _ := toolMap["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("tool[%d]: missing or empty 'name'", i)
		}

		desc, _ := toolMap["description"].(string)
		schema := toolMap["inputSchema"]

		tools = append(tools, ToolDefinition{
			Name:        name,
			Description: desc,
			InputSchema: schema,
		})
	}

	return tools, nil
}

// stringifyID normalizes a JSON-RPC ID (float64, string, or nil) to a map key.
func stringifyID(id interface{}) string {
	switch v := id.(type) {
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%g", v)
	case string:
		return v
	case nil:
		return "<nil>"
	default:
		return fmt.Sprintf("%v", v)
	}
}
