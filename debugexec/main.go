package main

import (
	"context"
	"fmt"
	"time"

	"whois/internal/utils"
)

func try(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := utils.ResolveValidatedTarget(ctx, target)
	fmt.Printf("in=%-28q -> resolved=%q err=%v\n", target, ip, err)
}

func main() {
	// Option-injection attempts: leading-hyphen targets that would become flags
	// if they ever reached `ping`/`traceroute` argv.
	for _, t := range []string{
		"-c", "-n", "-f", "--help", "-s 1500",
		"-t 9999", "8.8.8.8 -f", "8.8.8.8 -i 0.2",
		// Guard-bypass attempts: private/loopback/link-local variants
		"127.0.0.1", "127.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1",
		"localhost", "127.0.0.1.nip.io", "example.com",
	} {
		try(t)
	}
}
