package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// DiagnoseResult is the output of a preflight check.
type DiagnoseResult struct {
	Check   string `json:"check"`
	Status  string `json:"status"` // "ok", "warn", "fail"
	Detail  string `json:"detail,omitempty"`
}

// DiagnoseOutput is the complete diagnose output.
type DiagnoseOutput struct {
	Version string           `json:"version"`
	Checks  []DiagnoseResult `json:"checks"`
	OK      bool             `json:"ok"`
}

// RunDiagnose runs all preflight checks and prints JSON to stdout.
func RunDiagnose(socketPath, upstreamCmd, policyPath string) {
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
				Detail: fmt.Sprintf("not reachable at %s (subprocess fallback will be used)", socketPath),
			})
		}
	} else {
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "daemon",
			Status: "warn",
			Detail: "no socket path configured",
		})
	}

	// 2. Check upstream command findable
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

	// 3. Check avakill CLI available (for subprocess fallback)
	avakillPath, err := exec.LookPath("avakill")
	if err == nil {
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "avakill-cli",
			Status: "ok",
			Detail: avakillPath,
		})
	} else {
		output.Checks = append(output.Checks, DiagnoseResult{
			Check:  "avakill-cli",
			Status: "warn",
			Detail: "avakill not found in PATH (subprocess fallback unavailable)",
		})
	}

	// 4. Check policy file exists (if specified)
	if policyPath != "" {
		if _, err := os.Stat(policyPath); err == nil {
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "policy",
				Status: "ok",
				Detail: policyPath,
			})
		} else {
			allOK = false
			output.Checks = append(output.Checks, DiagnoseResult{
				Check:  "policy",
				Status: "fail",
				Detail: fmt.Sprintf("%s: %v", policyPath, err),
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

	output.OK = allOK

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Fprintln(os.Stdout, string(data))

	if !allOK {
		os.Exit(1)
	}
}
