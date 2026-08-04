package service

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"whois/internal/utils"
)

var PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204
	return exec.CommandContext(ctx, name, args...)
}

func Ping(ctx context.Context, target string, count int, callback func(string)) {
	resolvedTarget, err := utils.ResolveValidatedTarget(ctx, target)
	if err != nil {
		callback("Error: invalid or disallowed target for ping: " + err.Error())
		return
	}
	target = resolvedTarget

	countStr := fmt.Sprintf("%d", count)
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = PingCommandRunner(ctx, "ping", "-n", countStr, target)
	} else {
		cmd = PingCommandRunner(ctx, "ping", "-c", countStr, target)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		callback(fmt.Sprintf("Error: %v", err))
		return
	}
	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Error: %v", err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		callback(scanner.Text())
	}

	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		callback("Error: ping failed: " + err.Error())
	}
}
