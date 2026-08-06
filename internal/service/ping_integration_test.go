//go:build integration

package service

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"whois/internal/utils"
)

func TestPing_LoopbackIntegration(t *testing.T) {
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("ping executable is not installed")
	}
	previous := utils.GetAllowLoopbackIPs()
	utils.SetAllowLoopbackIPs(true)
	t.Cleanup(func() { utils.SetAllowLoopbackIPs(previous) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output []string
	if err := Ping(ctx, "127.0.0.1", 1, func(line string) { output = append(output, line) }); err != nil {
		t.Fatalf("loopback ping failed on %s: %v\n%s", runtime.GOOS, err, strings.Join(output, "\n"))
	}
	if len(output) == 0 {
		t.Fatal("loopback ping produced no output")
	}
}
