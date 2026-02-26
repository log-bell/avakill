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
