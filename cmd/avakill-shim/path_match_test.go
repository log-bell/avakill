package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePath_AbsolutePassthrough(t *testing.T) {
	got := normalizePath("/etc/passwd", "")
	if got != "/etc/passwd" {
		t.Errorf("expected /etc/passwd, got %q", got)
	}
}

func TestNormalizePath_TraversalCollapsed(t *testing.T) {
	got := normalizePath("/tmp/../etc/passwd", "")
	if got != "/etc/passwd" {
		t.Errorf("expected /etc/passwd, got %q", got)
	}
}

func TestNormalizePath_DotSegments(t *testing.T) {
	got := normalizePath("/tmp/./../../etc/passwd", "")
	if got != "/etc/passwd" {
		t.Errorf("expected /etc/passwd, got %q", got)
	}
}

func TestNormalizePath_MultipleSlashes(t *testing.T) {
	got := normalizePath("///etc///passwd", "")
	if got != "/etc/passwd" {
		t.Errorf("expected /etc/passwd, got %q", got)
	}
}

func TestNormalizePath_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	got := normalizePath("~/.ssh/id_rsa", "")
	expected := filepath.Join(home, ".ssh", "id_rsa")
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestNormalizePath_RelativeWithWorkspace(t *testing.T) {
	got := normalizePath("src/main.go", "/home/alice/project")
	if got != "/home/alice/project/src/main.go" {
		t.Errorf("expected /home/alice/project/src/main.go, got %q", got)
	}
}

func TestNormalizePath_RelativeWithoutWorkspace(t *testing.T) {
	// Should resolve against cwd
	got := normalizePath("foo.txt", "")
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
}

func TestNormalizePath_Empty(t *testing.T) {
	got := normalizePath("", "")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestNormalizePath_TraversalOutOfWorkspace(t *testing.T) {
	got := normalizePath("../../etc/passwd", "/home/alice/project")
	if got != "/home/etc/passwd" {
		t.Errorf("expected /home/etc/passwd, got %q", got)
	}
}

// --- matchPath tests ---

func TestMatchPath_ExactMatch(t *testing.T) {
	if !matchPath("/etc/passwd", []string{"/etc/passwd"}, "") {
		t.Error("expected exact match")
	}
}

func TestMatchPath_ExactNoMatch(t *testing.T) {
	if matchPath("/etc/shadow", []string{"/etc/passwd"}, "") {
		t.Error("expected no match")
	}
}

func TestMatchPath_DirectoryPrefix(t *testing.T) {
	if !matchPath("/etc/passwd", []string{"/etc/"}, "") {
		t.Error("expected /etc/ to match /etc/passwd")
	}
}

func TestMatchPath_DirectoryPrefixBoundary(t *testing.T) {
	// CVE-2025-53110: /etc/ must NOT match /etcetera/file
	if matchPath("/etcetera/file", []string{"/etc/"}, "") {
		t.Error("/etc/ must not match /etcetera/file (CVE-2025-53110)")
	}
}

func TestMatchPath_DirectoryPrefixExactDir(t *testing.T) {
	// /etc/ should match /etc itself (the directory)
	if !matchPath("/etc", []string{"/etc/"}, "") {
		t.Error("/etc/ should match /etc itself")
	}
}

func TestMatchPath_DirectoryPrefixNested(t *testing.T) {
	if !matchPath("/etc/nginx/nginx.conf", []string{"/etc/"}, "") {
		t.Error("expected /etc/ to match nested path")
	}
}

func TestMatchPath_TraversalResistance(t *testing.T) {
	// /tmp/../etc/passwd normalizes to /etc/passwd, should match /etc/
	normalized := normalizePath("/tmp/../etc/passwd", "")
	if !matchPath(normalized, []string{"/etc/"}, "") {
		t.Error("traversal path should match after normalization")
	}
}

func TestMatchPath_GlobSingleStar(t *testing.T) {
	if !matchPath("/home/alice/Documents", []string{"/home/*/Documents"}, "") {
		t.Error("expected glob * to match single segment")
	}
}

func TestMatchPath_GlobStarDoesNotCrossSlash(t *testing.T) {
	// * should NOT match across path separators
	if matchPath("/home/alice/sub/Documents", []string{"/home/*/Documents"}, "") {
		t.Error("glob * should not match across path separators")
	}
}

func TestMatchPath_GlobExtension(t *testing.T) {
	if !matchPath("/tmp/script.sh", []string{"/tmp/*.sh"}, "") {
		t.Error("expected glob to match extension")
	}
}

func TestMatchPath_RecursiveGlob(t *testing.T) {
	if !matchPath("/var/log/syslog", []string{"/var/log/**"}, "") {
		t.Error("expected /** to match file under dir")
	}
}

func TestMatchPath_RecursiveGlobNested(t *testing.T) {
	if !matchPath("/var/log/nginx/access.log", []string{"/var/log/**"}, "") {
		t.Error("expected /** to match nested file")
	}
}

func TestMatchPath_RecursiveGlobDirItself(t *testing.T) {
	if !matchPath("/var/log", []string{"/var/log/**"}, "") {
		t.Error("expected /** to match the dir itself")
	}
}

func TestMatchPath_RecursiveGlobNoMatch(t *testing.T) {
	if matchPath("/var/cache/apt", []string{"/var/log/**"}, "") {
		t.Error("expected /** not to match unrelated dir")
	}
}

func TestMatchPath_TildeInPattern(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}
	path := filepath.Join(home, ".ssh", "id_rsa")
	if !matchPath(path, []string{"~/.ssh/"}, "") {
		t.Error("expected ~/ pattern to match after expansion")
	}
}

func TestMatchPath_WorkspaceToken(t *testing.T) {
	if !matchPath("/home/alice/project/src/main.go", []string{"${workspace}/"}, "/home/alice/project") {
		t.Error("expected ${workspace} to expand and match")
	}
}

func TestMatchPath_WorkspaceTokenOutside(t *testing.T) {
	if matchPath("/etc/passwd", []string{"${workspace}/"}, "/home/alice/project") {
		t.Error("path outside workspace should not match")
	}
}

func TestMatchPath_MultiplePatterns(t *testing.T) {
	if !matchPath("/root/.bashrc", []string{"/etc/", "/root/"}, "") {
		t.Error("expected match on second pattern")
	}
}

func TestMatchPath_NoPatterns(t *testing.T) {
	if matchPath("/etc/passwd", []string{}, "") {
		t.Error("no patterns should never match")
	}
}

// --- extractPaths tests ---

func TestExtractPaths_KnownKey(t *testing.T) {
	args := map[string]interface{}{
		"path": "/etc/passwd",
	}
	paths := extractPaths(args)
	if len(paths) != 1 || paths[0] != "/etc/passwd" {
		t.Errorf("expected [/etc/passwd], got %v", paths)
	}
}

func TestExtractPaths_MultipleKnownKeys(t *testing.T) {
	args := map[string]interface{}{
		"source":      "/tmp/a.txt",
		"destination": "/tmp/b.txt",
	}
	paths := extractPaths(args)
	if len(paths) != 2 {
		t.Errorf("expected 2 paths, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_FilePathKey(t *testing.T) {
	args := map[string]interface{}{
		"file_path": "/home/user/doc.txt",
	}
	paths := extractPaths(args)
	if len(paths) != 1 {
		t.Errorf("expected 1 path, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_AbsolutePathValue(t *testing.T) {
	// Non-standard key but value is an absolute path
	args := map[string]interface{}{
		"location": "/var/log/syslog",
	}
	paths := extractPaths(args)
	if len(paths) != 1 {
		t.Errorf("expected 1 path from absolute value, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_TildeValue(t *testing.T) {
	args := map[string]interface{}{
		"target": "~/.ssh/id_rsa",
	}
	paths := extractPaths(args)
	if len(paths) != 1 {
		t.Errorf("expected 1 path, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_NonPathValues(t *testing.T) {
	args := map[string]interface{}{
		"command": "ls -la",
		"count":   float64(5),
		"verbose": true,
	}
	paths := extractPaths(args)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_NilArgs(t *testing.T) {
	paths := extractPaths(nil)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d", len(paths))
	}
}

func TestExtractPaths_EmptyStringValue(t *testing.T) {
	args := map[string]interface{}{
		"path": "",
	}
	paths := extractPaths(args)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for empty string, got %d", len(paths))
	}
}

func TestExtractPaths_NonStringNonNumericIgnored(t *testing.T) {
	args := map[string]interface{}{
		"options": map[string]interface{}{"a": 1},
	}
	paths := extractPaths(args)
	if len(paths) != 0 {
		t.Errorf("expected 0 paths, got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_NoDuplicates(t *testing.T) {
	// Same path under known key AND detected as absolute — should appear once
	args := map[string]interface{}{
		"path": "/etc/passwd",
	}
	paths := extractPaths(args)
	if len(paths) != 1 {
		t.Errorf("expected 1 path (no duplicates), got %d: %v", len(paths), paths)
	}
}

func TestExtractPaths_RelativePathInKnownKey(t *testing.T) {
	args := map[string]interface{}{
		"file": "src/main.go",
	}
	paths := extractPaths(args)
	if len(paths) != 1 || paths[0] != "src/main.go" {
		t.Errorf("expected [src/main.go], got %v", paths)
	}
}

// --- detectWorkspaceRoot tests ---

func TestDetectWorkspaceRoot_EnvVar(t *testing.T) {
	t.Setenv("AVAKILL_WORKSPACE", "/custom/workspace")
	got := detectWorkspaceRoot()
	if got != "/custom/workspace" {
		t.Errorf("expected /custom/workspace, got %q", got)
	}
}

func TestDetectWorkspaceRoot_FallbackToCwd(t *testing.T) {
	t.Setenv("AVAKILL_WORKSPACE", "")
	got := detectWorkspaceRoot()
	if got == "" {
		t.Error("expected non-empty workspace root")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
}

// --- Edge cases ---

func TestNormalizePath_NullByte(t *testing.T) {
	// Null byte in path should be preserved (caller may reject,
	// but normalization shouldn't hide it)
	got := normalizePath("/etc\x00/../passwd", "")
	// filepath.Clean doesn't strip null bytes — verify it's still absolute
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
}

func TestNormalizePath_SpacesInPath(t *testing.T) {
	got := normalizePath("/home/user/My Documents/file.txt", "")
	if got != "/home/user/My Documents/file.txt" {
		t.Errorf("expected spaces preserved, got %q", got)
	}
}

func TestMatchPath_RootPattern(t *testing.T) {
	// "/" as a directory prefix pattern should match everything
	if !matchPath("/anything/here", []string{"/"}, "") {
		t.Error("root / pattern should match all absolute paths")
	}
}

func TestMatchPath_EmptyPath(t *testing.T) {
	if matchPath("", []string{"/etc/"}, "") {
		t.Error("empty path should not match")
	}
}

func TestExtractPaths_FilePathVariants(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		expected bool
	}{
		{"path", "/a", true},
		{"file", "/a", true},
		{"filename", "/a", true},
		{"file_path", "/a", true},
		{"filepath", "/a", true},
		{"directory", "/a", true},
		{"dir", "/a", true},
		{"target", "/a", true},
		{"destination", "/a", true},
		{"dest", "/a", true},
		{"source", "/a", true},
		{"src", "/a", true},
		{"dst", "/a", true},
		{"PATH", "/a", true}, // case-insensitive key
		{"File", "/a", true}, // case-insensitive key
	}
	for _, tc := range tests {
		args := map[string]interface{}{tc.key: tc.value}
		paths := extractPaths(args)
		got := len(paths) > 0
		if got != tc.expected {
			t.Errorf("extractPaths({%q: %q}): got extracted=%v, want %v",
				tc.key, tc.value, got, tc.expected)
		}
	}
}

func TestMatchPath_DirPrefixNoTrailingSlashInPath(t *testing.T) {
	// Pattern "/etc/" with path "/etc" (no trailing slash) → should match
	if !matchPath("/etc", []string{"/etc/"}, "") {
		t.Error("/etc should match /etc/ pattern (the directory itself)")
	}
}
