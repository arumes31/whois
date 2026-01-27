package service

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

func Traceroute(ctx context.Context, target string, callback func(string)) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tracert", "-d", target)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute", "-n", target)
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
	_ = cmd.Wait()
}
