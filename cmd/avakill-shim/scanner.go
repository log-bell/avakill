package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ScanFinding represents a single finding from response scanning.
type ScanFinding struct {
	Category    string // "secrets", "pii", "injection", "custom"
	PatternName string // e.g. "aws_access_key", "email"
	MatchedText string // truncated to 60 chars
	Action      string // effective action for this finding
}

// Scanner holds compiled patterns and performs content scanning.
// All fields are read-only after construction; safe for concurrent use.
type Scanner struct {
	secretPatterns    []compiledPattern
	piiPatterns       []compiledPattern
	injectionPatterns []compiledPattern
	customPatterns    []compiledPattern
	safeDomains       map[string]bool
	defaultAction     string
}

// compiledPattern holds a pre-compiled regex with metadata.
type compiledPattern struct {
	name      string
	preFilter string         // strings.Contains fast-reject before regex
	regex     *regexp.Regexp
	action    string // empty = use defaultAction
	category  string
}

// patternDef defines a pattern before compilation.
type patternDef struct {
	name      string
	category  string
	regex     string
	preFilter string
}

var secretPatternDefs = []patternDef{
	{name: "aws_access_key", category: "secrets", regex: `AKIA[0-9A-Z]{16}`, preFilter: "AKIA"},
	{name: "github_token", category: "secrets", regex: `gh[pos]_[A-Za-z0-9_]{36,}`, preFilter: "gh"},
	{name: "github_fine_grained", category: "secrets", regex: `github_pat_[A-Za-z0-9_]{82,}`, preFilter: "github_pat_"},
	{name: "gitlab_token", category: "secrets", regex: `glpat-[A-Za-z0-9\-_]{20,}`, preFilter: "glpat-"},
	{name: "slack_token", category: "secrets", regex: `xox[baprs]-[0-9a-zA-Z-]{10,}`, preFilter: "xox"},
	{name: "jwt", category: "secrets", regex: `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`, preFilter: "eyJ"},
	{name: "private_key", category: "secrets", regex: `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, preFilter: "PRIVATE KEY"},
	{name: "generic_api_key", category: "secrets", regex: `(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?`, preFilter: ""},
	{name: "database_url", category: "secrets", regex: `(?i)(?:postgres|mysql|mongodb|redis)://[^\s'"]+`, preFilter: "://"},
	{name: "anthropic_key", category: "secrets", regex: `sk-ant-[A-Za-z0-9_-]{90,}`, preFilter: "sk-ant-"},
	{name: "openai_key", category: "secrets", regex: `sk-[A-Za-z0-9]{48,}`, preFilter: "sk-"},
	{name: "stripe_key", category: "secrets", regex: `[rs]k_(?:test|live)_[A-Za-z0-9]{24,}`, preFilter: "k_"},
	{name: "heroku_api_key", category: "secrets", regex: `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, preFilter: "-"},
}

var piiPatternDefs = []patternDef{
	{name: "email", category: "pii", regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, preFilter: "@"},
	{name: "us_phone", category: "pii", regex: `(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`, preFilter: ""},
	{name: "ssn", category: "pii", regex: `\b\d{3}-\d{2}-\d{4}\b`, preFilter: "-"},
	{name: "credit_card", category: "pii", regex: `\b\d{4}[-\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b`, preFilter: ""},
}

var injectionPatternDefs = []patternDef{
	{name: "important_tag", category: "injection", regex: `(?i)<\s*IMPORTANT\s*>`, preFilter: "<"},
	{name: "markdown_exfil", category: "injection", regex: `!\[[^\]]*\]\(https?://[^)\s]*`, preFilter: "!["},
	{name: "ignore_instructions", category: "injection", regex: `(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions`, preFilter: ""},
	{name: "system_prompt_leak", category: "injection", regex: `(?i)system\s+prompt\s*:`, preFilter: ""},
	{name: "system_tag", category: "injection", regex: `(?i)<\s*system\s*>`, preFilter: "<"},
}

// NewScanner compiles all enabled patterns and returns a Scanner.
// Built-in patterns use MustCompile (panics on bad regex = programmer error).
// Custom patterns use Compile with error propagation.
func NewScanner(cfg *ScanConfig) (*Scanner, error) {
	s := &Scanner{
		safeDomains:   make(map[string]bool),
		defaultAction: cfg.Action,
	}

	for _, d := range cfg.SafeDomains {
		s.safeDomains[strings.ToLower(d)] = true
	}

	if cfg.ScanSecrets {
		s.secretPatterns = compileBuiltinPatterns(secretPatternDefs)
	}
	if cfg.ScanPII {
		s.piiPatterns = compileBuiltinPatterns(piiPatternDefs)
	}
	if cfg.ScanInjection {
		s.injectionPatterns = compileBuiltinPatterns(injectionPatternDefs)
	}

	for _, cp := range cfg.CustomPatterns {
		re, err := regexp.Compile(cp.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile custom pattern %q: %w", cp.Name, err)
		}
		s.customPatterns = append(s.customPatterns, compiledPattern{
			name:     cp.Name,
			regex:    re,
			action:   cp.Action,
			category: "custom",
		})
	}

	return s, nil
}

// compileBuiltinPatterns compiles a slice of built-in pattern definitions.
func compileBuiltinPatterns(defs []patternDef) []compiledPattern {
	out := make([]compiledPattern, len(defs))
	for i, d := range defs {
		out[i] = compiledPattern{
			name:      d.name,
			preFilter: d.preFilter,
			regex:     regexp.MustCompile(d.regex),
			category:  d.category,
		}
	}
	return out
}

// ScanContent scans text for all matching patterns and returns findings.
// Returns nil if no findings.
func (s *Scanner) ScanContent(text string) []ScanFinding {
	var findings []ScanFinding
	textLower := strings.ToLower(text)

	scanGroup := func(patterns []compiledPattern) {
		for i := range patterns {
			p := &patterns[i]

			// Pre-filter: fast reject before regex
			if p.preFilter != "" {
				if !strings.Contains(text, p.preFilter) && !strings.Contains(textLower, strings.ToLower(p.preFilter)) {
					continue
				}
			}

			matches := p.regex.FindAllString(text, -1)
			for _, match := range matches {
				// Post-filter: markdown_exfil domain check
				if p.name == "markdown_exfil" && s.isSafeDomain(match) {
					continue
				}

				action := p.action
				if action == "" {
					action = s.defaultAction
				}

				matched := match
				if len(matched) > 60 {
					matched = matched[:60]
				}

				findings = append(findings, ScanFinding{
					Category:    p.category,
					PatternName: p.name,
					MatchedText: matched,
					Action:      action,
				})
			}
		}
	}

	scanGroup(s.secretPatterns)
	scanGroup(s.piiPatterns)
	scanGroup(s.injectionPatterns)
	scanGroup(s.customPatterns)

	return findings
}

// RedactAll replaces all pattern matches with [REDACTED:<category>].
func (s *Scanner) RedactAll(text string) string {
	textLower := strings.ToLower(text)

	redactGroup := func(patterns []compiledPattern) {
		for i := range patterns {
			p := &patterns[i]

			if p.preFilter != "" {
				if !strings.Contains(text, p.preFilter) && !strings.Contains(textLower, strings.ToLower(p.preFilter)) {
					continue
				}
			}

			replacement := "[REDACTED:" + p.category + "]"

			if p.name == "markdown_exfil" && len(s.safeDomains) > 0 {
				// Only redact matches to unsafe domains
				text = p.regex.ReplaceAllStringFunc(text, func(match string) string {
					if s.isSafeDomain(match) {
						return match
					}
					return replacement
				})
			} else {
				text = p.regex.ReplaceAllString(text, replacement)
			}

			// Update lower for subsequent pre-filter checks
			textLower = strings.ToLower(text)
		}
	}

	redactGroup(s.secretPatterns)
	redactGroup(s.piiPatterns)
	redactGroup(s.injectionPatterns)
	redactGroup(s.customPatterns)

	return text
}

// isSafeDomain checks if a markdown image match references a safe domain.
func (s *Scanner) isSafeDomain(match string) bool {
	if len(s.safeDomains) == 0 {
		return false
	}

	// Extract URL from markdown image pattern: ![...](https://domain/...
	idx := strings.Index(match, "(")
	if idx < 0 {
		return false
	}
	rawURL := match[idx+1:]
	// Trim trailing paren if present
	rawURL = strings.TrimSuffix(rawURL, ")")

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	if s.safeDomains[host] {
		return true
	}
	// Subdomain match: images.example.com matches safe domain example.com
	for domain := range s.safeDomains {
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// resolveAction returns the highest-severity action from findings.
// Precedence: block > redact > log.
func resolveAction(findings []ScanFinding) string {
	best := "log"
	for _, f := range findings {
		switch f.Action {
		case "block":
			return "block" // can't go higher
		case "redact":
			best = "redact"
		}
	}
	return best
}
