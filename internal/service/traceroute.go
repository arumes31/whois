package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"whois/internal/utils"
)

var CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204
	return exec.CommandContext(ctx, name, args...)
}

func Traceroute(ctx context.Context, target string, callback func(string)) {
	resolvedTarget, err := utils.ResolveValidatedTarget(ctx, target)
	if err != nil {
		callback("Error: invalid or disallowed target for traceroute: " + err.Error())
		return
	}
	target = resolvedTarget

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = CommandRunner(ctx, "tracert", "-d", "-h", "20", target)
	} else {
		// Use -m 20 to limit hops and -q 1 for speed (one probe per hop)
		cmd = CommandRunner(ctx, "traceroute", "-n", "-m", "20", "-q", "1", target)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		callback(fmt.Sprintf("Failed to capture traceroute output: %v", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		callback(fmt.Sprintf("Failed to capture traceroute errors: %v", err))
		return
	}

	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Failed to start traceroute: %v", err))
		return
	}

	type traceLine struct {
		text   string
		stdout bool
	}
	lines := make(chan traceLine, 32)
	var scanWG sync.WaitGroup
	scan := func(reader io.Reader, prefix string, isStdout bool) {
		defer scanWG.Done()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if isStdout && strings.TrimSpace(line) == "" {
				continue
			}
			lines <- traceLine{text: prefix + line, stdout: isStdout}
		}
		if err := scanner.Err(); err != nil {
			lines <- traceLine{text: prefix + "output read failed: " + err.Error()}
			_, _ = io.Copy(io.Discard, reader)
		}
	}
	scanWG.Add(2)
	go scan(stdout, "", true)
	go scan(stderr, "Error: ", false)
	go func() {
		scanWG.Wait()
		close(lines)
	}()

	outputFound := false
	for line := range lines {
		if line.stdout {
			outputFound = true
		}
		callback(line.text)
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		callback("Traceroute failed: " + err.Error())
	}

	if !outputFound {
		callback("Traceroute produced no output. It might be blocked or the utility might be missing.")
	}
}
