package main

import (
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// KillSwitch provides an emergency mechanism to instantly deny ALL tool calls.
// Tracks two independent engagement sources:
//   - fileEngaged: managed by sentinel file polling (machine-wide)
//   - manualEngaged: managed by Engage()/Disengage() and signal handlers (per-process)
//
// IsEngaged() returns true if EITHER source is active.
type KillSwitch struct {
	filePath          string
	mu                sync.RWMutex
	fileEngaged       bool
	fileReason        string
	manualEngaged     bool
	manualReason      string
	engagedAt         time.Time
	fileCheckInterval time.Duration
	stopCh            chan struct{}
	verbose           bool
}

// NewKillSwitch creates a new KillSwitch monitoring the given sentinel file path.
// Call Start() to begin file polling and signal handling.
func NewKillSwitch(filePath string) *KillSwitch {
	return &KillSwitch{
		filePath:          filePath,
		fileCheckInterval: 1 * time.Second,
		stopCh:            make(chan struct{}),
	}
}

// IsEngaged returns whether the kill switch is currently engaged and the reason.
// This is the hot-path check called on every tool call — just a RLock + two bool reads.
func (ks *KillSwitch) IsEngaged() (bool, string) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if ks.manualEngaged {
		return true, ks.manualReason
	}
	if ks.fileEngaged {
		return true, ks.fileReason
	}
	return false, ""
}

// Engage activates the kill switch programmatically with the given reason.
func (ks *KillSwitch) Engage(reason string) {
	ks.mu.Lock()
	ks.manualEngaged = true
	ks.manualReason = reason
	if ks.engagedAt.IsZero() {
		ks.engagedAt = time.Now()
	}
	ks.mu.Unlock()
}

// Disengage deactivates the kill switch (clears BOTH sources) and removes
// the sentinel file if it exists.
func (ks *KillSwitch) Disengage() {
	ks.mu.Lock()
	ks.manualEngaged = false
	ks.manualReason = ""
	ks.fileEngaged = false
	ks.fileReason = ""
	ks.engagedAt = time.Time{}
	ks.mu.Unlock()

	// Remove sentinel file if it exists
	os.Remove(ks.filePath)
}

// Start performs a synchronous initial file check, then begins background
// polling and signal handling. If the sentinel file exists at startup,
// the kill switch starts engaged.
func (ks *KillSwitch) Start() {
	ks.checkFile()
	go ks.pollLoop()
	ks.startSignalHandler()
}

// Stop stops the background polling goroutine.
func (ks *KillSwitch) Stop() {
	close(ks.stopCh)
}

// pollLoop runs checkFile periodically until stopped.
func (ks *KillSwitch) pollLoop() {
	ticker := time.NewTicker(ks.fileCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ks.checkFile()
		case <-ks.stopCh:
			return
		}
	}
}

// checkFile checks the sentinel file and updates ONLY the file-engagement state.
// Does not affect manual (signal/programmatic) engagement.
// Fail-closed: any stat error other than "not exist" engages the switch.
func (ks *KillSwitch) checkFile() {
	_, err := os.Stat(ks.filePath)

	if os.IsNotExist(err) {
		ks.mu.Lock()
		ks.fileEngaged = false
		ks.fileReason = ""
		ks.mu.Unlock()
		return
	}

	// File exists (err == nil) OR stat failed (fail-closed) — engage
	reason := ks.readSentinelReason()

	ks.mu.Lock()
	ks.fileEngaged = true
	ks.fileReason = reason
	if ks.engagedAt.IsZero() {
		ks.engagedAt = time.Now()
	}
	ks.mu.Unlock()
}

// readSentinelReason reads the sentinel file contents as the denial reason.
// Returns a default reason on any read error.
func (ks *KillSwitch) readSentinelReason() string {
	data, err := os.ReadFile(ks.filePath)
	if err != nil {
		return "kill switch engaged (sentinel file unreadable)"
	}
	reason := strings.TrimSpace(string(data))
	if reason == "" {
		return "kill switch engaged via sentinel file"
	}
	return reason
}

// startSignalHandler registers SIGUSR1 (engage) and SIGUSR2 (disengage).
func (ks *KillSwitch) startSignalHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1, syscall.SIGUSR2)

	go func() {
		for {
			select {
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGUSR1:
					ks.Engage("kill switch engaged via SIGUSR1")
				case syscall.SIGUSR2:
					ks.Disengage()
				}
			case <-ks.stopCh:
				signal.Stop(sigCh)
				return
			}
		}
	}()
}
