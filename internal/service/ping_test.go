package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
	utils.SetAllowPrivateIPs(true)
}

func TestPing(t *testing.T) {
	found := false
	_ = Ping(context.Background(), "127.0.0.1", 1, func(line string) {
		l := strings.ToLower(line)
		if strings.Contains(l, "reply from") || strings.Contains(l, "64 bytes from") || strings.Contains(l, "127.0.0.1") {
			found = true
		}
	})

	if !found {
		t.Log("Ping output did not contain expected patterns (might be environment specific)")
	}
}

func TestPing_InvalidTarget(t *testing.T) {
	hasError := false
	err := Ping(context.Background(), "invalid!target", 1, func(line string) {
		if strings.Contains(line, "Error") {
			hasError = true
		}
	})
	if err == nil {
		t.Fatal("invalid target returned nil error")
	}
	if !hasError {
		t.Error("Expected error for invalid target")
	}
}

func TestPing_Cancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Ping(ctx, "8.8.8.8", 1, func(string) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ping error = %v, want context.Canceled", err)
	}
}

func TestPing_Mocked(t *testing.T) {
	oldRunner := PingCommandRunner
	defer func() { PingCommandRunner = oldRunner }()

	t.Run("Success", func(t *testing.T) {
		PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			cs := []string{"-test.run=TestHelperProcess", "--", name}
			cs = append(cs, args...)
			cmd := exec.Command(os.Args[0], cs...)
			cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_STDOUT=Reply from 1.1.1.1"}
			return cmd
		}
		found := false
		err := Ping(context.Background(), "1.1.1.1", 1, func(line string) {
			if strings.Contains(line, "Reply") {
				found = true
			}
		})
		if err != nil {
			t.Fatalf("mocked ping failed: %v", err)
		}
		if !found {
			t.Error("Expected Reply in output")
		}
	})

	t.Run("Error Start", func(t *testing.T) {
		PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.Command("non-existent-command-12345")
		}
		hasError := false
		err := Ping(context.Background(), "1.1.1.1", 1, func(line string) {
			if strings.Contains(line, "Error") {
				hasError = true
			}
		})
		if err == nil {
			t.Fatal("command-start failure returned nil error")
		}
		if !hasError {
			t.Error("Expected Error in output")
		}
	})

	t.Run("Stderr Detail", func(t *testing.T) {
		PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", name)
			cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_STDERR=network unreachable"}
			return cmd
		}
		var lines []string
		err := Ping(context.Background(), "1.1.1.1", 1, func(line string) {
			lines = append(lines, line)
		})
		if err != nil {
			t.Fatalf("successful stderr diagnostic returned error: %v", err)
		}
		if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "Error: network unreachable") {
			t.Fatalf("ping did not surface stderr detail: %v", lines)
		}
	})

	t.Run("Scanner Error Drains Output", func(t *testing.T) {
		PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--", name)
			cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "HELPER_LONG_STDOUT=1"}
			return cmd
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var lines []string
		err := Ping(ctx, "1.1.1.1", 1, func(line string) {
			lines = append(lines, line)
		})
		if err != nil {
			t.Fatalf("ping failed after draining oversized output: %v", err)
		}
		if !strings.Contains(strings.Join(lines, "\n"), "output read failed") {
			t.Fatalf("scanner error was not surfaced: %v", lines)
		}
	})
}
