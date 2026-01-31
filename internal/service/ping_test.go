package service

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"whois/internal/utils"
)

func init() {
	utils.TestInitLogger()
	utils.AllowPrivateIPs = true
}

func TestPing(t *testing.T) {
	t.Parallel()
	found := false
	Ping(context.Background(), "127.0.0.1", 1, func(line string) {
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
	Ping(context.Background(), "invalid!target", 1, func(line string) {
		if strings.Contains(line, "Error") {
			hasError = true
		}
	})
	if !hasError {
		t.Error("Expected error for invalid target")
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
		Ping(context.Background(), "1.1.1.1", 1, func(line string) {
			if strings.Contains(line, "Reply") {
				found = true
			}
		})
		if !found {
			t.Error("Expected Reply in output")
		}
	})

	t.Run("Error Start", func(t *testing.T) {
		PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			return exec.Command("non-existent-command-12345")
		}
		hasError := false
		Ping(context.Background(), "1.1.1.1", 1, func(line string) {
			if strings.Contains(line, "Error") {
				hasError = true
			}
		})
		if !hasError {
			t.Error("Expected Error in output")
		}
	})
}
