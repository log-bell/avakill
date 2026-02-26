package main

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// dangerousBuiltins is the set of shell builtins/commands that enable
// arbitrary code execution even without metacharacters.
var dangerousBuiltins = map[string]bool{
	"eval":   true,
	"source": true,
	"exec":   true,
	"xargs":  true,
}

// ShellAnalysis holds security-relevant features extracted from a shell
// command's AST in a single parse-and-walk pass.
type ShellAnalysis struct {
	Pipes               bool
	Redirects           bool
	CommandSubstitution bool
	VariableExpansion   bool
	Subshells           bool
	BackgroundJobs      bool
	ProcessSubstitution bool
	DangerousBuiltins   []string // e.g. eval, source, exec, xargs
	Segments            []string // text of each leaf-level command
	BaseCommands        []string // first word of each simple command (quote-resolved)
	ParseError          bool
}

// analyzeCommand parses a shell command string into an AST and walks it
// once to extract all security-relevant features.
func analyzeCommand(cmd string) ShellAnalysis {
	var a ShellAnalysis

	if cmd == "" {
		return a
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		a.ParseError = true
		return a
	}

	seen := make(map[string]bool) // dedup dangerous builtins

	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Stmt:
			if n.Background {
				a.BackgroundJobs = true
			}

		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				a.Pipes = true
			}

		case *syntax.Redirect:
			a.Redirects = true

		case *syntax.CmdSubst:
			a.CommandSubstitution = true

		case *syntax.ParamExp:
			a.VariableExpansion = true

		case *syntax.Subshell:
			a.Subshells = true

		case *syntax.ProcSubst:
			a.ProcessSubstitution = true

		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				name := resolveWord(n.Args[0])
				if name != "" {
					a.BaseCommands = append(a.BaseCommands, name)
					if dangerousBuiltins[name] && !seen[name] {
						a.DangerousBuiltins = append(a.DangerousBuiltins, name)
						seen[name] = true
					}
				}
				// Collect as a segment: reconstruct from the word parts
				var seg strings.Builder
				for i, w := range n.Args {
					if i > 0 {
						seg.WriteByte(' ')
					}
					seg.WriteString(printWord(w))
				}
				s := seg.String()
				if s != "" {
					a.Segments = append(a.Segments, s)
				}
			}
		}
		return true
	})

	return a
}

// resolveWord concatenates a Word's parts into a single string,
// stripping quotes. This resolves bypass techniques like w'h'o'am'i → whoami.
// Returns empty string if the word contains unexpandable parts
// (variable expansions, command substitutions, etc.).
func resolveWord(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			// Double-quoted: concatenate literal parts only
			for _, dp := range p.Parts {
				switch dv := dp.(type) {
				case *syntax.Lit:
					sb.WriteString(dv.Value)
				default:
					// Contains expansion — can't resolve statically
					return sb.String()
				}
			}
		default:
			// ParamExp, CmdSubst, etc. — can't resolve
			return sb.String()
		}
	}
	return sb.String()
}

// shellInterpreters is the set of commands that can execute arbitrary
// code when piped into.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true,
}

// isShellSafe checks whether a shell command is safe to execute based on
// AST analysis and an optional command allowlist.
//
// When allowlist is non-empty, every base command in the input must appear
// in the allowlist. When allowlist is empty, the function checks for
// dangerous structural features (command substitution, process substitution,
// dangerous builtins, pipe-to-shell patterns).
//
// Returns (safe, reason). reason is empty when safe is true.
func isShellSafe(cmd string, allowlist []string) (bool, string) {
	if cmd == "" {
		return true, ""
	}

	a := analyzeCommand(cmd)

	if a.ParseError {
		return false, "unparseable command (fail-closed)"
	}

	// Allowlist mode: every base command must be in the list
	if len(allowlist) > 0 {
		allowed := make(map[string]bool, len(allowlist))
		for _, c := range allowlist {
			allowed[c] = true
		}
		for _, base := range a.BaseCommands {
			if !allowed[base] {
				return false, "command '" + base + "' not in allowlist"
			}
		}
		return true, ""
	}

	// No allowlist: check for dangerous structural features
	if a.CommandSubstitution {
		return false, "command substitution detected"
	}
	if a.ProcessSubstitution {
		return false, "process substitution detected"
	}
	if len(a.DangerousBuiltins) > 0 {
		return false, "dangerous builtin: " + strings.Join(a.DangerousBuiltins, ", ")
	}

	// Pipe to shell interpreter
	if a.Pipes {
		for _, base := range a.BaseCommands {
			if shellInterpreters[base] {
				return false, "pipe to shell interpreter: " + base
			}
		}
	}

	return true, ""
}

// splitCompoundCommand splits a compound shell command into individual
// segments using AST parsing. Returns the original command as a single
// segment on parse error.
func splitCompoundCommand(cmd string) []string {
	if cmd == "" {
		return nil
	}

	a := analyzeCommand(cmd)

	if a.ParseError {
		return []string{cmd}
	}

	return a.Segments
}

// printWord reconstructs a Word's text representation from its parts.
func printWord(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteByte('\'')
			sb.WriteString(p.Value)
			sb.WriteByte('\'')
		case *syntax.DblQuoted:
			sb.WriteByte('"')
			for _, dp := range p.Parts {
				switch dv := dp.(type) {
				case *syntax.Lit:
					sb.WriteString(dv.Value)
				default:
					// For other parts, use a placeholder
					sb.WriteString("$?")
				}
			}
			sb.WriteByte('"')
		default:
			sb.WriteString("$?")
		}
	}
	return sb.String()
}
