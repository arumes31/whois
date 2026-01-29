package service

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

func Ping(ctx context.Context, target string, count int, callback func(string)) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", fmt.Sprintf("%d", count), target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", fmt.Sprintf("%d", count), target)
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Failed to start ping: %v", err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		callback(scanner.Text())
	}

	errScanner := bufio.NewScanner(stderr)
	for errScanner.Scan() {
		callback("Error: " + errScanner.Text())
	}

	_ = cmd.Wait()
}
