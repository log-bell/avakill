package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

func main() {
	socketPath := flag.String("socket", defaultSocketPath(), "Daemon socket path")
	policyPath := flag.String("policy", "", "Policy file for subprocess fallback")
	diagnose := flag.Bool("diagnose", false, "Run preflight checks and exit")
	version := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("verbose", false, "Detailed stderr diagnostics")
	pinTools := flag.Bool("pin-tools", false, "Pin tool definitions on first tools/list and exit")
	killFlag := flag.Bool("kill", false, "Create kill switch sentinel file and exit")
	killReason := flag.String("kill-reason", "", "Reason for kill switch activation (used with --kill)")
	unkillFlag := flag.Bool("unkill", false, "Remove kill switch sentinel file and exit")
	killswitchFile := flag.String("killswitch-file", defaultKillSwitchPath(), "Kill switch sentinel file path")

	flag.Parse()

	if *version {
		fmt.Fprintf(os.Stdout, "avakill-shim %s\n", Version)
		os.Exit(0)
	}

	if *killFlag {
		path := expandHome(*killswitchFile)
		os.MkdirAll(filepath.Dir(path), 0700)
		reason := *killReason
		if reason == "" {
			reason = "kill switch engaged via --kill"
		}
		if err := os.WriteFile(path, []byte(reason), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "avakill-shim: failed to create sentinel file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "avakill-shim: kill switch ENGAGED (%s)\n", path)
		os.Exit(0)
	}

	if *unkillFlag {
		path := expandHome(*killswitchFile)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "avakill-shim: failed to remove sentinel file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "avakill-shim: kill switch DISENGAGED (%s)\n", path)
		os.Exit(0)
	}

	// Everything after -- is the upstream command and its args
	remaining := flag.Args()

	if *diagnose {
		upstreamCmd := ""
		serverCommand := ""
		if len(remaining) > 0 {
			upstreamCmd = remaining[0]
			serverCommand = strings.Join(remaining, " ")
		}
		RunDiagnose(*socketPath, upstreamCmd, serverCommand, *policyPath, *killswitchFile)
		return
	}

	if len(remaining) == 0 {
		fmt.Fprintln(os.Stderr, "avakill-shim: upstream command required (usage: avakill-shim [flags] -- <command> [args...])")
		flag.Usage()
		os.Exit(1)
	}

	upstreamCmd := remaining[0]
	upstreamArgs := remaining[1:]

	// Recover shell environment
	env, err := RecoverShellEnv()
	if err != nil {
		if *verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: shell env recovery failed: %v (using system env)\n", err)
		}
		env = nil
	} else if *verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: recovered %d env vars\n", len(env))
	}

	// Resolve upstream binary in recovered environment
	resolvedCmd, err := ResolveInEnv(upstreamCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "avakill-shim: cannot find upstream command %q: %v\n", upstreamCmd, err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: resolved %s → %s\n", upstreamCmd, resolvedCmd)
	}

	// Spawn upstream process
	cmd := exec.Command(resolvedCmd, upstreamArgs...)
	cmd.Stderr = os.Stderr

	// Use recovered environment if available
	if env != nil {
		cmd.Env = EnvToSlice(env)
	}

	upstreamStdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "avakill-shim: stdin pipe: %v\n", err)
		os.Exit(1)
	}

	upstreamStdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "avakill-shim: stdout pipe: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "avakill-shim: failed to start upstream: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: upstream started (pid %d)\n", cmd.Process.Pid)
	}

	// Handle signals — forward to upstream
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		if *verbose {
			fmt.Fprintf(os.Stderr, "avakill-shim: received %v, forwarding to upstream\n", sig)
		}
		cmd.Process.Signal(sig)
	}()

	// Set up kill switch
	ks := NewKillSwitch(expandHome(*killswitchFile))
	ks.Start()
	defer ks.Stop()

	// Set up evaluator
	evaluator := &Evaluator{
		SocketPath: *socketPath,
		PolicyPath: *policyPath,
		Verbose:    *verbose,
		KillSwitch: ks,
	}

	// Set up tool hash detection and response scanning
	var toolHasher *ToolHasher
	var toolHashCfg *ToolHashConfig
	var pinToolsDone chan struct{}
	var scanner *Scanner
	var scanCfg *ScanConfig

	// Build the full server command string for manifest keying
	serverCommand := strings.Join(remaining, " ")

	if *pinTools {
		// --pin-tools mode: create config for one-shot pinning
		home, _ := os.UserHomeDir()
		manifestDir := filepath.Join(home, ".avakill", "tool-manifests")
		toolHashCfg = &ToolHashConfig{
			Enabled:        true,
			Action:         "log",
			ManifestDir:    manifestDir,
			PinOnFirstSeen: true,
		}
		toolHasher = NewToolHasher(manifestDir, *verbose)
		pinToolsDone = make(chan struct{})
	} else if *policyPath != "" {
		cfg, err := loadPolicyFile(*policyPath)
		if err == nil {
			// Tool hashing
			if cfg.ToolHash != nil && cfg.ToolHash.Enabled {
				toolHashCfg = cfg.ToolHash
				toolHasher = NewToolHasher(cfg.ToolHash.ManifestDir, *verbose)
			}
			// Response scanning
			if cfg.ResponseScan != nil && cfg.ResponseScan.Enabled {
				scanCfg = cfg.ResponseScan
				s, serr := NewScanner(cfg.ResponseScan)
				if serr != nil {
					fmt.Fprintf(os.Stderr, "avakill-shim: fatal: bad scanner config: %v\n", serr)
					os.Exit(1)
				}
				scanner = s
				if *verbose {
					fmt.Fprintf(os.Stderr, "avakill-shim: response scanning enabled (action=%s)\n", scanCfg.Action)
				}
			}
		}
	}

	// Run proxy
	proxy := &Proxy{
		Evaluator:       evaluator,
		Verbose:         *verbose,
		ToolHasher:      toolHasher,
		ToolHashCfg:     toolHashCfg,
		ServerCommand:   serverCommand,
		PinToolsMode:    *pinTools,
		PinToolsDone:    pinToolsDone,
		Scanner:         scanner,
		ScanCfg:         scanCfg,
		pendingRequests: make(map[string]string),
	}

	// Only initialize pendingRequests when tool hashing or scanning is active
	if toolHasher == nil && scanner == nil {
		proxy.pendingRequests = nil
	}

	if *pinTools {
		// Run proxy in background, wait for pin or timeout
		go func() {
			proxy.Run(os.Stdin, os.Stdout, upstreamStdout, upstreamStdin)
		}()

		select {
		case <-pinToolsDone:
			fmt.Fprintln(os.Stderr, "avakill-shim: tool definitions pinned successfully")
		case <-time.After(30 * time.Second):
			fmt.Fprintln(os.Stderr, "avakill-shim: timeout waiting for tools/list response")
		}

		// Kill upstream and exit
		cmd.Process.Kill()
		cmd.Wait()
		return
	}

	proxyErr := proxy.Run(os.Stdin, os.Stdout, upstreamStdout, upstreamStdin)

	// Wait for upstream to exit (proxy already closed upstreamStdin on client EOF)
	waitErr := cmd.Wait()

	if proxyErr != nil && *verbose {
		fmt.Fprintf(os.Stderr, "avakill-shim: proxy error: %v\n", proxyErr)
	}

	// Exit with upstream's exit code
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

// defaultKillSwitchPath returns the default kill switch sentinel file path.
func defaultKillSwitchPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".avakill", "killswitch")
}

// defaultSocketPath returns the default daemon socket path.
func defaultSocketPath() string {
	if p := os.Getenv("AVAKILL_SOCKET"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".avakill", "avakill.sock")
}
