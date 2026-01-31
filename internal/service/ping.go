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
	return exec.CommandContext(ctx, name, args...)
}

func Ping(ctx context.Context, target string, count int, callback func(string)) {
	if !utils.IsValidTarget(target) {
		callback("Error: invalid target for ping")
		return
	}

	countStr := fmt.Sprintf("%d", count)
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = PingCommandRunner(ctx, "ping", "-n", countStr, target)
	} else {
		cmd = PingCommandRunner(ctx, "ping", "-c", countStr, target)
	}

	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Error: %v", err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		callback(scanner.Text())
	}

	_ = cmd.Wait()
}
