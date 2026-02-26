package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// normalizePath resolves a raw path string to a canonical absolute path.
//
// Expands ~ to home directory, collapses . and .. segments, removes
// duplicate slashes. Does NOT resolve symlinks — the path may reference
// a remote filesystem accessed through an MCP server.
//
// Relative paths are resolved against workspaceRoot if provided,
// otherwise against the current working directory.
func normalizePath(raw string, workspaceRoot string) string {
	if raw == "" {
		return ""
	}

	// Expand ~ (reuse existing expandHome from env.go)
	expanded := expandHome(raw)

	// Clean: collapse ., .., multiple slashes
	cleaned := filepath.Clean(expanded)

	// Make absolute
	if !filepath.IsAbs(cleaned) {
		if workspaceRoot != "" {
			cleaned = filepath.Join(workspaceRoot, cleaned)
		} else {
			if abs, err := filepath.Abs(cleaned); err == nil {
				cleaned = abs
			}
		}
	}

	return cleaned
}

// matchPath checks if a normalized absolute path matches any of the given patterns.
//
// Pattern types:
//   - Exact path: "/etc/passwd" matches only "/etc/passwd"
//   - Directory prefix: "/etc/" matches "/etc/passwd" but NOT "/etcetera/file"
//     (separator-boundary matching — fixes CVE-2025-53110 pattern)
//   - Glob: "/home/*/Documents" uses filepath.Match (* does not cross /)
//   - Recursive glob: "/var/log/**" matches any depth under /var/log
//   - Home expansion: "~/.ssh/" expands ~ to user's home directory
//   - Workspace token: "${workspace}/" replaced with workspaceRoot
func matchPath(normalizedPath string, patterns []string, workspaceRoot string) bool {
	for _, raw := range patterns {
		if matchSinglePattern(normalizedPath, raw, workspaceRoot) {
			return true
		}
	}
	return false
}

// matchSinglePattern checks one pattern against a normalized path.
func matchSinglePattern(normalizedPath string, rawPattern string, workspaceRoot string) bool {
	pattern := rawPattern

	// Detect pattern type BEFORE expansion (trailing / is meaningful
	// and may be stripped by filepath.Join inside expandHome)
	isDirPrefix := strings.HasSuffix(pattern, "/")
	hasDoubleStar := strings.Contains(pattern, "**")

	// Expand ${workspace}
	if workspaceRoot != "" {
		pattern = strings.ReplaceAll(pattern, "${workspace}", workspaceRoot)
	}

	// Expand ~
	pattern = expandHome(pattern)

	switch {
	case hasDoubleStar:
		return matchDoubleStar(normalizedPath, pattern)
	case isDirPrefix:
		return matchDirPrefix(normalizedPath, pattern)
	case containsGlobMeta(pattern):
		cleaned := filepath.Clean(pattern)
		matched, _ := filepath.Match(cleaned, normalizedPath)
		return matched
	default:
		// Exact match
		cleaned := filepath.Clean(pattern)
		return normalizedPath == cleaned
	}
}

// matchDirPrefix checks if path equals or is under the given directory.
// "/etc/" matches "/etc", "/etc/passwd", "/etc/nginx/conf" but NOT "/etcetera".
func matchDirPrefix(path string, dirPattern string) bool {
	dir := filepath.Clean(dirPattern)
	if path == dir {
		return true
	}
	// Special case: root "/" matches all absolute paths
	if dir == "/" {
		return strings.HasPrefix(path, "/")
	}
	return strings.HasPrefix(path, dir+string(filepath.Separator))
}

// matchDoubleStar handles ** recursive glob patterns.
//
// Common patterns:
//   - "/var/log/**" → matches anything under /var/log (directory prefix)
//   - "**/secret" → matches "secret" at any depth (not yet needed, but supported)
func matchDoubleStar(path string, pattern string) bool {
	// Most common: suffix /** — treat as directory prefix
	if strings.HasSuffix(pattern, "/**") {
		prefix := filepath.Clean(strings.TrimSuffix(pattern, "/**"))
		if path == prefix {
			return true
		}
		return strings.HasPrefix(path, prefix+string(filepath.Separator))
	}

	// General case: split on segments and match recursively
	pathSegs := splitPath(path)
	patSegs := splitPath(filepath.Clean(pattern))
	return matchSegments(pathSegs, patSegs)
}

// splitPath splits an absolute path into segments, dropping empty segments.
func splitPath(p string) []string {
	parts := strings.Split(p, string(filepath.Separator))
	result := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// matchSegments matches path segments against pattern segments.
// "**" in pattern matches zero or more segments.
// "*" matches any single segment component (like filepath.Match).
func matchSegments(path []string, pattern []string) bool {
	return matchSegsRecursive(path, 0, pattern, 0)
}

func matchSegsRecursive(path []string, pi int, pattern []string, qi int) bool {
	// Both exhausted → match
	if pi == len(path) && qi == len(pattern) {
		return true
	}

	// Pattern exhausted but path remains → no match
	if qi == len(pattern) {
		return false
	}

	seg := pattern[qi]

	if seg == "**" {
		// ** matches zero or more path segments
		// Try matching zero segments (skip **)
		if matchSegsRecursive(path, pi, pattern, qi+1) {
			return true
		}
		// Try consuming one path segment and keeping **
		if pi < len(path) {
			return matchSegsRecursive(path, pi+1, pattern, qi)
		}
		return false
	}

	// Path exhausted but pattern remains (and it's not **) → no match
	if pi == len(path) {
		return false
	}

	// Single segment match (supports * and ? via filepath.Match)
	matched, _ := filepath.Match(seg, path[pi])
	if !matched {
		return false
	}

	return matchSegsRecursive(path, pi+1, pattern, qi+1)
}

// containsGlobMeta returns true if the string contains glob metacharacters.
func containsGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// pathArgKeys lists argument keys commonly used for file paths by MCP tools.
var pathArgKeys = map[string]bool{
	"path":        true,
	"file":        true,
	"filename":    true,
	"file_path":   true,
	"filepath":    true,
	"directory":   true,
	"dir":         true,
	"target":      true,
	"destination": true,
	"dest":        true,
	"source":      true,
	"src":         true,
	"dst":         true,
}

// extractPaths extracts path-like string values from tool call arguments.
//
// Two extraction strategies:
//  1. Values under known path-related keys (path, file, dir, etc.)
//  2. String values that look like absolute paths (start with / or ~)
//
// Returns raw (un-normalized) path strings. The caller should normalize
// them with normalizePath before matching.
func extractPaths(args map[string]interface{}) []string {
	if args == nil {
		return nil
	}

	seen := make(map[string]bool)
	var paths []string

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			paths = append(paths, s)
		}
	}

	for key, val := range args {
		str, ok := val.(string)
		if !ok {
			continue
		}

		lowerKey := strings.ToLower(key)

		// Strategy 1: known path keys — always include the value
		if pathArgKeys[lowerKey] {
			add(str)
			continue
		}

		// Strategy 2: heuristic — value looks like a path
		if isPathLike(str) {
			add(str)
		}
	}

	return paths
}

// isPathLike returns true if the string looks like a filesystem path.
func isPathLike(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "~/") ||
		s == "~" ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../")
}

// detectWorkspaceRoot returns the workspace root directory.
//
// Priority:
//  1. AVAKILL_WORKSPACE environment variable
//  2. Walk up from cwd looking for .git
//  3. Fall back to cwd
//
// Not cached — called per-evaluation. Use AVAKILL_WORKSPACE env var
// for zero-cost resolution in performance-sensitive contexts.
// For cached access, use cachedWorkspaceRoot() instead.
func detectWorkspaceRoot() string {
	if ws := os.Getenv("AVAKILL_WORKSPACE"); ws != "" {
		return filepath.Clean(ws)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	dir := cwd
	for {
		if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return cwd
}

var (
	workspaceOnce sync.Once
	workspaceRoot string
)

// cachedWorkspaceRoot returns the workspace root, resolving it only once per process.
func cachedWorkspaceRoot() string {
	workspaceOnce.Do(func() {
		workspaceRoot = detectWorkspaceRoot()
	})
	return workspaceRoot
}
