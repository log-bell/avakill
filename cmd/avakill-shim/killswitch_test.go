package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKillSwitch_ProgrammaticEngage(t *testing.T) {
	dir := t.TempDir()
	ks := NewKillSwitch(filepath.Join(dir, "killswitch"))

	engaged, reason := ks.IsEngaged()
	if engaged {
		t.Fatal("expected disengaged initially")
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %q", reason)
	}

	ks.Engage("compromised session")

	engaged, reason = ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged after Engage()")
	}
	if reason != "compromised session" {
		t.Fatalf("expected reason 'compromised session', got %q", reason)
	}
}

func TestKillSwitch_ProgrammaticDisengage(t *testing.T) {
	dir := t.TempDir()
	ks := NewKillSwitch(filepath.Join(dir, "killswitch"))

	ks.Engage("test reason")
	ks.Disengage()

	engaged, _ := ks.IsEngaged()
	if engaged {
		t.Fatal("expected disengaged after Disengage()")
	}
}

func TestKillSwitch_Disengage_RemovesSentinelFile(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	os.WriteFile(sentinelPath, []byte("test"), 0644)

	ks := NewKillSwitch(sentinelPath)
	ks.Engage("test")
	ks.Disengage()

	if _, err := os.Stat(sentinelPath); !os.IsNotExist(err) {
		t.Fatal("expected sentinel file to be removed after Disengage()")
	}
}

func TestKillSwitch_FileActivation(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	engaged, _ := ks.IsEngaged()
	if engaged {
		t.Fatal("expected disengaged initially")
	}

	os.WriteFile(sentinelPath, []byte(""), 0644)
	time.Sleep(150 * time.Millisecond)

	engaged, _ = ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged after sentinel file created")
	}
}

func TestKillSwitch_FileDeactivation(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	os.WriteFile(sentinelPath, []byte(""), 0644)

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	time.Sleep(150 * time.Millisecond)
	engaged, _ := ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged with sentinel file present")
	}

	os.Remove(sentinelPath)
	time.Sleep(150 * time.Millisecond)

	engaged, _ = ks.IsEngaged()
	if engaged {
		t.Fatal("expected disengaged after sentinel file removed")
	}
}

func TestKillSwitch_FileWithReason(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	os.WriteFile(sentinelPath, []byte("compromised session"), 0644)

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	time.Sleep(150 * time.Millisecond)

	engaged, reason := ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged")
	}
	if reason != "compromised session" {
		t.Fatalf("expected reason 'compromised session', got %q", reason)
	}
}

func TestKillSwitch_FileIsDirectory_FailClosed(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	os.Mkdir(sentinelPath, 0755)

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	time.Sleep(150 * time.Millisecond)

	engaged, _ := ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged when sentinel is a directory (fail-closed)")
	}
}

func TestKillSwitch_FileNoReadPermission_FailClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: root can read anything")
	}

	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	os.WriteFile(sentinelPath, []byte("secret"), 0000)

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	time.Sleep(150 * time.Millisecond)

	engaged, _ := ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged when sentinel has no read permission (fail-closed)")
	}
}

func TestKillSwitch_StartsEngagedIfFileExists(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	os.WriteFile(sentinelPath, []byte("pre-existing"), 0644)

	ks := NewKillSwitch(sentinelPath)
	ks.Start()
	defer ks.Stop()

	// Should be engaged immediately after Start (synchronous initial check)
	engaged, reason := ks.IsEngaged()
	if !engaged {
		t.Fatal("expected engaged on startup when sentinel file exists")
	}
	if reason != "pre-existing" {
		t.Fatalf("expected reason 'pre-existing', got %q", reason)
	}
}

func TestKillSwitch_SignalSurvivesFilePoll(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")
	// No sentinel file — only signal engagement

	ks := NewKillSwitch(sentinelPath)
	ks.fileCheckInterval = 50 * time.Millisecond
	ks.Start()
	defer ks.Stop()

	// Engage programmatically (simulates signal handler)
	ks.Engage("SIGUSR1 simulation")

	// Wait for several poll cycles
	time.Sleep(200 * time.Millisecond)

	// Should STILL be engaged — file poll must not clear manual engagement
	engaged, reason := ks.IsEngaged()
	if !engaged {
		t.Fatal("manual engagement was cleared by file poll — dual-source tracking broken")
	}
	if reason != "SIGUSR1 simulation" {
		t.Fatalf("expected manual reason, got %q", reason)
	}
}
