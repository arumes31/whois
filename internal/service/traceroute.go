package service

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"whois/internal/utils"
)

func Traceroute(ctx context.Context, target string, callback func(string)) {
	if !utils.IsValidTarget(target) {
		callback("Error: invalid target for traceroute")
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", "20", target)
	} else {
		// Use -m 20 to limit hops and -q 1 for speed (one probe per hop)
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", "20", "-q", "1", target)
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Failed to start traceroute: %v", err))
		return
	}

	outputFound := false
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			outputFound = true
			callback(line)
		}
	}

	errScanner := bufio.NewScanner(stderr)
	for errScanner.Scan() {
		callback("Error: " + errScanner.Text())
	}

	_ = cmd.Wait()

	if !outputFound {
		callback("Traceroute produced no output. It might be blocked or the utility might be missing.")
	}
}
