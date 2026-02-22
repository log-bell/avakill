package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	envCache   map[string]string
	envOnce    sync.Once
	envErr     error
	envTimeout = 5 * time.Second
)

// RecoverShellEnv recovers the user's interactive shell environment.
// Runs `$SHELL -ilc env` and parses the output. Results are cached.
func RecoverShellEnv() (map[string]string, error) {
	envOnce.Do(func() {
		envCache, envErr = doRecoverShellEnv()
	})
	return envCache, envErr
}

func doRecoverShellEnv() (map[string]string, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell, "-ilc", "env")
	cmd.Stderr = nil // Suppress shell startup noise

	// Set a timeout
	done := make(chan error, 1)
	var out []byte

	go func() {
		var err error
		out, err = cmd.Output()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("shell env recovery failed: %w", err)
		}
	case <-time.After(envTimeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil, fmt.Errorf("shell env recovery timed out after %v", envTimeout)
	}

	return parseEnv(string(out)), nil
}

// parseEnv parses `env` output into a map.
func parseEnv(output string) map[string]string {
	env := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := line[:idx]
		val := line[idx+1:]
		env[key] = val
	}
	return env
}

// ResolveInEnv looks up a binary name in the recovered shell PATH.
// Falls back to the system PATH if shell recovery fails.
func ResolveInEnv(name string) (string, error) {
	env, err := RecoverShellEnv()
	if err == nil {
		if path, ok := env["PATH"]; ok {
			for _, dir := range strings.Split(path, ":") {
				candidate := dir + "/" + name
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
					return candidate, nil
				}
			}
		}
	}

	// Fallback: system exec.LookPath
	return exec.LookPath(name)
}

// EnvToSlice converts the recovered env map to os/exec-compatible slice.
func EnvToSlice(env map[string]string) []string {
	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, k+"="+v)
	}
	return result
}

// ResetEnvCache clears the cached environment (for testing).
func ResetEnvCache() {
	envOnce = sync.Once{}
	envCache = nil
	envErr = nil
}
