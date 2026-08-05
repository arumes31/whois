package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTraceroute_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = Traceroute(ctx, "8.8.8.8", func(line string) {})
}

func TestTraceroute_InvalidTarget(t *testing.T) {
	_ = Traceroute(context.Background(), "invalid!target", func(line string) {})
}

// Mocking exec.Command via helper process
func TestTraceroute_Success(t *testing.T) {
	oldRunner := CommandRunner
	defer func() { CommandRunner = oldRunner }()

	CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", name}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_STDOUT=1 hop  1.1.1.1  1ms"}
		return cmd
	}

	lines := 0
	_ = Traceroute(context.Background(), "example.com", func(line string) {
		lines++
	})
	if lines == 0 {
		t.Error("Expected output from traceroute")
	}
}

func TestTraceroute_ErrorStart(t *testing.T) {
	oldRunner := CommandRunner
	defer func() { CommandRunner = oldRunner }()

	CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.Command("non-existent-command-12345")
	}

	failed := false
	_ = Traceroute(context.Background(), "example.com", func(line string) {
		if strings.Contains(line, "Failed to start") {
			failed = true
		}
	})
	if !failed {
		t.Error("Expected start failure")
	}
}

func TestTraceroute_Stderr(t *testing.T) {
	oldRunner := CommandRunner
	defer func() { CommandRunner = oldRunner }()

	CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", name}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_STDERR=Permission denied"}
		return cmd
	}

	hasError := false
	_ = Traceroute(context.Background(), "example.com", func(line string) {
		if strings.Contains(line, "Error: Permission denied") {
			hasError = true
		}
	})
	if !hasError {
		t.Error("Expected stderr output")
	}
}

func TestTracerouteDrainsStdoutAndStderrConcurrently(t *testing.T) {
	oldRunner := CommandRunner
	defer func() { CommandRunner = oldRunner }()

	CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--", name)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_LARGE_STDERR=1"}
		return cmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	foundHop := false
	_ = Traceroute(ctx, "example.com", func(line string) {
		if strings.Contains(line, "1.1.1.1") {
			foundHop = true
		}
	})
	if elapsed := time.Since(started); elapsed >= 9*time.Second {
		t.Fatalf("traceroute blocked while draining process output for %v", elapsed)
	}
	if !foundHop {
		t.Fatal("traceroute lost stdout while draining a full stderr pipe")
	}
}

func TestTracerouteAppliesOperationTimeout(t *testing.T) {
	oldRunner := CommandRunner
	defer func() { CommandRunner = oldRunner }()

	CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--", name)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_BLOCK=1"}
		return cmd
	}

	start := time.Now()
	timedOut := false
	_ = tracerouteWithTimeout(context.Background(), "8.8.8.8", 50*time.Millisecond, func(line string) {
		if strings.Contains(line, "timed out") {
			timedOut = true
		}
	})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded traceroute took %v", elapsed)
	}
	if !timedOut {
		t.Fatal("bounded traceroute did not report its timeout")
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if out := os.Getenv("HELPER_STDOUT"); out != "" {
		_, _ = fmt.Fprintln(os.Stdout, out)
	}
	if err := os.Getenv("HELPER_STDERR"); err != "" {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
	if os.Getenv("HELPER_LARGE_STDERR") == "1" {
		for range 512 {
			_, _ = fmt.Fprintln(os.Stderr, strings.Repeat("x", 1024))
		}
		_, _ = fmt.Fprintln(os.Stdout, "1 hop  1.1.1.1  1ms")
	}
	if os.Getenv("HELPER_BLOCK") == "1" {
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}
