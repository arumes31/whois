package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"sync"
	"whois/internal/utils"
)

var PingCommandRunner = func(ctx context.Context, name string, args ...string) *exec.Cmd {
	// #nosec G204
	return exec.CommandContext(ctx, name, args...)
}

func Ping(ctx context.Context, target string, count int, callback func(string)) error {
	resolvedTarget, err := utils.ResolveValidatedTarget(ctx, target)
	if err != nil {
		err = fmt.Errorf("invalid or disallowed target for ping: %w", err)
		callback("Error: " + err.Error())
		return err
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
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		callback(fmt.Sprintf("Error: %v", err))
		return err
	}
	if err := cmd.Start(); err != nil {
		callback(fmt.Sprintf("Error: %v", err))
		return err
	}

	type pingLine struct {
		text       string
		diagnostic bool
	}
	lines := make(chan pingLine, 16)
	var scanWG sync.WaitGroup
	scan := func(reader io.Reader, prefix string, diagnostic bool) {
		defer scanWG.Done()
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines <- pingLine{text: prefix + scanner.Text(), diagnostic: diagnostic}
		}
		if err := scanner.Err(); err != nil {
			lines <- pingLine{text: "Error: ping output read failed: " + err.Error(), diagnostic: true}
		}
	}
	scanWG.Add(2)
	go scan(stdout, "", false)
	go scan(stderr, "Error: ", true)
	go func() {
		scanWG.Wait()
		close(lines)
	}()

	diagnosticFound := false
	for line := range lines {
		diagnosticFound = diagnosticFound || line.diagnostic
		callback(line.text)
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !diagnosticFound {
			callback("Error: ping failed: " + err.Error())
		}
		return fmt.Errorf("ping failed: %w", err)
	}
	return nil
}
