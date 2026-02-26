package main

import (
	"os"
	"sync"
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
