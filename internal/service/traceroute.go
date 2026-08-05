package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"whois/internal/utils"
)

const tracerouteTimeout = 30 * time.Second

var CommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204
	return exec.CommandContext(ctx, name, args...)
}

func Traceroute(ctx context.Context, target string, callback func(string)) error {
	return tracerouteWithTimeout(ctx, target, tracerouteTimeout, callback)
}

func tracerouteWithTimeout(ctx context.Context, target string, timeout time.Duration, callback func(string)) error {
	traceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := traceCtx.Err(); err != nil {
		return err
	}
	resolvedTarget, err := utils.ResolveValidatedTarget(traceCtx, target)
	if err != nil {
		if errors.Is(traceCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			callback("Traceroute timed out after " + timeout.String())
			return context.DeadlineExceeded
		} else {
			callback("Error: invalid or disallowed target for traceroute: " + err.Error())
			return err
		}
	}
	target = resolvedTarget

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = CommandRunner(traceCtx, "tracert", "-d", "-h", "20", "-w", "2000", target)
	} else {
		// Use -m 20 to limit hops and -q 1 for speed (one probe per hop)
		cmd = CommandRunner(traceCtx, "traceroute", "-n", "-m", "20", "-q", "1", "-w", "2", target)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		callback(fmt.Sprintf("Failed to capture traceroute output: %v", err))
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		callback(fmt.Sprintf("Failed to capture traceroute errors: %v", err))
		return err
	}

	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Failed to start traceroute: %v", err))
		return err
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
			lines <- traceLine{text: prefix + "output read failed: " + err.Error(), stdout: isStdout}
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
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(traceCtx.Err(), context.DeadlineExceeded) {
			callback("Traceroute timed out after " + timeout.String())
			return context.DeadlineExceeded
		} else {
			callback("Traceroute failed: " + err.Error())
			return fmt.Errorf("traceroute failed: %w", err)
		}
	}

	if !outputFound && traceCtx.Err() == nil {
		err := errors.New("traceroute produced no output; it might be blocked or the utility might be missing")
		callback(err.Error())
		return err
	}
	if err := traceCtx.Err(); err != nil {
		return err
	}
	return nil
}
