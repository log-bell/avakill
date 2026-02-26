package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DiagnoseResult is the output of a preflight check.
type DiagnoseResult struct {
	Check  string `json:"check"`
	Status string `json:"status"` // "ok", "warn", "fail"
	Detail string `json:"detail,omitempty"`
}

// DiagnoseOutput is the complete diagnose output.
type DiagnoseOutput struct {
	Version string           `json:"version"`
	Checks  []DiagnoseResult `json:"checks"`
	OK      bool             `json:"ok"`
}

// RunDiagnose runs all preflight checks and prints JSON to stdout.
func RunDiagnose(socketPath, upstreamCmd, policyPath, killswitchFile string) {
	output := DiagnoseOutput{
		Version: Version,
		Checks:  make([]DiagnoseResult, 0),
	}

	allOK := true

	// 1. Check daemon reachable
	eval := &Evaluator{SocketPath: socketPath}
	if socketPath != "" {
		if eval.DaemonReachable() {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "daemon",
				Status: "ok",
				Detail: fmt.Sprintf("reachable at %s", socketPath),
			})
		} else {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "daemon",
				Status: "warn",
				Detail: fmt.Sprintf("not reachable at %s (in-process policy will be used if --policy is set)", socketPath),
			})
		}
	} else {
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "daemon",
			Status: "info",
			Detail: "no socket path configured (not needed when using --policy)",
		})
	}

	// 2. Check kill switch status
	{
		ksPath := expandHome(killswitchFile)
		info, err := os.Stat(ksPath)
		if os.IsNotExist(err) {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "killswitch",
				Status: "ok",
				Detail: fmt.Sprintf("disengaged (sentinel: %s)", ksPath),
			})
		} else if err != nil {
			allOK = false
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "killswitch",
				Status: "fail",
				Detail: fmt.Sprintf("ENGAGED (stat error, fail-closed: %v)", err),
			})
		} else {
			allOK = false
			reason := "no reason"
			if !info.IsDir() {
				if data, readErr := os.ReadFile(ksPath); readErr == nil && len(data) > 0 {
					reason = strings.TrimSpace(string(data))
				}
			}
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "killswitch",
				Status: "fail",
				Detail: fmt.Sprintf("ENGAGED — %s (sentinel: %s)", reason, ksPath),
			})
		}
	}

	// 3. Check upstream command findable
	if upstreamCmd != "" {
		resolved, err := ResolveInEnv(upstreamCmd)
		if err == nil {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "upstream",
				Status: "ok",
				Detail: fmt.Sprintf("%s → %s", upstreamCmd, resolved),
			})
		} else {
			allOK = false
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "upstream",
				Status: "fail",
				Detail: fmt.Sprintf("%s not found in PATH: %v", upstreamCmd, err),
			})
		}
	} else {
		allOK = false
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "upstream",
			Status: "fail",
			Detail: "no upstream command specified (usage: avakill-shim [flags] -- <command>)",
		})
	}

	// 3. Check avakill CLI available (informational — subprocess fallback removed)
	output.Checks = append(output.Checks, DiagnoseResult{
		Check:  "avakill-cli",
		Status: "info",
		Detail: "subprocess fallback removed; in-process policy evaluation is used instead",
	})

	// 4. Check policy file (if specified): parse and validate YAML
	if policyPath != "" {
		cfg, err := loadPolicyFile(policyPath)
		if err != nil {
			allOK = false
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "policy",
				Status: "fail",
				Detail: fmt.Sprintf("%s: %v", policyPath, err),
			})
		} else {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "policy",
				Status: "ok",
				Detail: fmt.Sprintf("%s (%d rules, default_action=%s)", policyPath, len(cfg.Policies), cfg.DefaultAction),
			})
		}
	}

	// 5. Check shell env recovery
	ResetEnvCache()
	env, err := RecoverShellEnv()
	if err == nil {
		pathLen := len(env["PATH"])
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "shell-env",
			Status: "ok",
			Detail: fmt.Sprintf("recovered %d vars, PATH length %d", len(env), pathLen),
		})
	} else {
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "shell-env",
			Status: "warn",
			Detail: fmt.Sprintf("recovery failed: %v (system PATH will be used)", err),
		})
	}

	// 6. Check tool manifests
	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		manifestDir := filepath.Join(home, ".avakill", "tool-manifests")
		entries, err := os.ReadDir(manifestDir)
		if err != nil {
			if os.IsNotExist(err) {
				output.Checks = append(output.Checks, DiagnoseResult{
					Check:  "tool-manifests",
					Status: "info",
					Detail: "no tool manifests found (tool hashing not yet used)",
				})
			} else {
				output.Checks = append(output.Checks, DiagnoseResult{
					Check:  "tool-manifests",
					Status: "warn",
					Detail: fmt.Sprintf("cannot read manifest dir: %v", err),
				})
			}
		} else {
			count := 0
			for _, e := range entries {
				if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
					count++
				}
			}
			detail := fmt.Sprintf("%d manifest(s) in %s", count, manifestDir)
			// If upstream command provided, show its manifest details
			if upstreamCmd != "" {
				serverCmd := upstreamCmd
				mPath := manifestPath(manifestDir, serverCmd)
				m, err := loadManifest(mPath)
				if err == nil {
					detail += fmt.Sprintf("; server %q: %d tools pinned", serverCmd, len(m.Tools))
				}
			}
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "tool-manifests",
				Status: "ok",
				Detail: detail,
			})
		}
	}

	output.OK = allOK

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(os.Stdout, string(data))

	if !allOK {
		os.Exit(1)
	}
}
