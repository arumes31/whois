package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTraceroute_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Traceroute(ctx, "8.8.8.8", func(line string) {})
}

func TestTraceroute_InvalidTarget(t *testing.T) {
	Traceroute(context.Background(), "invalid!target", func(line string) {})
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
	Traceroute(context.Background(), "example.com", func(line string) {
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
	Traceroute(context.Background(), "example.com", func(line string) {
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
	Traceroute(context.Background(), "example.com", func(line string) {
		if strings.Contains(line, "Error: Permission denied") {
			hasError = true
		}
	})
	if !hasError {
		t.Error("Expected stderr output")
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
	os.Exit(0)
}
