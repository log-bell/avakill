package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

func main() {
	socketPath := flag.String("socket", defaultSocketPath(), "Daemon socket path")
	policyPath := flag.String("policy", "", "Policy file for subprocess fallback")
	diagnose := flag.Bool("diagnose", false, "Run preflight checks and exit")
	version := flag.Bool("version", false, "Print version and exit")
	verbose := flag.Bool("verbose", false, "Detailed stderr diagnostics")

	flag.Parse()

	if *version {
		fmt.Fprintf(os.Stdout, "avakill-shim %s\n", Version)
		os.Exit(0)
	}

	// Everything after -- is the upstream command and its args
	remaining := flag.Args()

	if *diagnose {
		upstreamCmd := ""
		if len(remaining) > 0 {
			upstreamCmd = remaining[0]
		}
		RunDiagnose(*socketPath, upstreamCmd, *policyPath)
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

	// Set up evaluator
	evaluator := &Evaluator{
		SocketPath: *socketPath,
		PolicyPath: *policyPath,
		Verbose:    *verbose,
	}

	// Run proxy
	proxy := &Proxy{
		Evaluator: evaluator,
		Verbose:   *verbose,
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
