//go:build !stress

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"whois/internal/service"
	"whois/internal/utils"

	"golang.org/x/mod/semver"
)

// TestV2Integration validates all changes introduced in the v2 update.
func TestV2Integration(t *testing.T) {
	// =========================================================================
	// 3.1 Go Version Validation
	// =========================================================================
	t.Run("GoVersion", func(t *testing.T) {
		t.Run("GoModVersionAtLeast1264", func(t *testing.T) {
			data, err := os.ReadFile("go.mod")
			if err != nil {
				t.Fatalf("failed to read go.mod: %v", err)
			}
			re := regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`)
			matches := re.FindSubmatch(data)
			if len(matches) < 2 {
				t.Fatal("no Go version directive found in go.mod")
			}
			version := string(matches[1])
			if semver.Compare("v"+version, "v1.26.4") < 0 {
				t.Errorf("expected Go version >= 1.26.4 in go.mod, got %q", version)
			}
		})

		t.Run("DockerfileBuilderImage", func(t *testing.T) {
			data, err := os.ReadFile("Dockerfile")
			if err != nil {
				t.Fatalf("failed to read Dockerfile: %v", err)
			}
			if !strings.Contains(string(data), "golang:1.26-alpine") {
				t.Error("expected Dockerfile builder image to use golang:1.26-alpine, but it was not found")
			}
		})

		t.Run("DockerfileRuntimeImagePinned", func(t *testing.T) {
			data, err := os.ReadFile("Dockerfile")
			if err != nil {
				t.Fatalf("failed to read Dockerfile: %v", err)
			}
			if strings.Contains(string(data), "alpine:latest") {
				t.Error("Dockerfile runtime image must not use alpine:latest (unpinned); expected a pinned version like alpine:3.x")
			}
			re := regexp.MustCompile(`FROM\s+alpine:\d+\.\d+`)
			if !re.Match(data) {
				t.Error("expected Dockerfile runtime image to use a pinned alpine version (e.g. alpine:3.21), but none was found")
			}
		})
	})

	// =========================================================================
	// 3.2 PR Integration Validation
	// =========================================================================
	t.Run("PRIntegration", func(t *testing.T) {
		t.Run("PRAriaLabels_FooterCloseModal", func(t *testing.T) {
			data, err := os.ReadFile("templates/footer.html")
			if err != nil {
				t.Fatalf("failed to read templates/footer.html: %v", err)
			}
			if !strings.Contains(string(data), `aria-label="Close modal"`) {
				t.Error(`expected templates/footer.html to contain aria-label="Close modal" (PR #29), but it was not found`)
			}
		})

		t.Run("PRAriaLabels_IndexCloseWidget", func(t *testing.T) {
			data, err := os.ReadFile("templates/index.html")
			if err != nil {
				t.Fatalf("failed to read templates/index.html: %v", err)
			}
			if !strings.Contains(string(data), `aria-label="Close widget"`) {
				t.Error(`expected templates/index.html to contain aria-label="Close widget" (PR #29), but it was not found`)
			}
		})

		t.Run("DockerPublishLoginActionV4", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/docker-publish.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/docker-publish.yml: %v", err)
			}
			if !strings.Contains(string(data), "docker/login-action@v4") {
				t.Error("expected .github/workflows/docker-publish.yml to use docker/login-action@v4 (PR #28), but it was not found")
			}
		})

		t.Run("DockerPublishBuildPushActionV7", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/docker-publish.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/docker-publish.yml: %v", err)
			}
			if !strings.Contains(string(data), "docker/build-push-action@v7") {
				t.Error("expected .github/workflows/docker-publish.yml to use docker/build-push-action@v7 (PR #27), but it was not found")
			}
		})

		t.Run("DockerTestCheckoutV6", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/docker-test.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/docker-test.yml: %v", err)
			}
			if !strings.Contains(string(data), "actions/checkout@v6") {
				t.Error("expected .github/workflows/docker-test.yml to use actions/checkout@v6 (PR #24), but it was not found")
			}
		})

		t.Run("DockerTestLoginActionV4", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/docker-test.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/docker-test.yml: %v", err)
			}
			if !strings.Contains(string(data), "docker/login-action@v4") {
				t.Error("expected .github/workflows/docker-test.yml to use docker/login-action@v4 (PR #28), but it was not found")
			}
		})

		t.Run("DockerTestBuildPushActionV7", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/docker-test.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/docker-test.yml: %v", err)
			}
			if !strings.Contains(string(data), "docker/build-push-action@v7") {
				t.Error("expected .github/workflows/docker-test.yml to use docker/build-push-action@v7 (PR #27), but it was not found")
			}
		})

		t.Run("GoCICheckoutV6", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/go-ci.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/go-ci.yml: %v", err)
			}
			if !strings.Contains(string(data), "actions/checkout@v6") {
				t.Error("expected .github/workflows/go-ci.yml to use actions/checkout@v6 (PR #24), but it was not found")
			}
		})

		t.Run("GoCISetupGoV6", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/go-ci.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/go-ci.yml: %v", err)
			}
			if !strings.Contains(string(data), "actions/setup-go@v6") {
				t.Error("expected .github/workflows/go-ci.yml to use actions/setup-go@v6 (PR #23), but it was not found")
			}
		})

		t.Run("GoCIGolangciLintActionV9", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/go-ci.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/go-ci.yml: %v", err)
			}
			if !strings.Contains(string(data), "golangci/golangci-lint-action@v9") {
				t.Error("expected .github/workflows/go-ci.yml to use golangci/golangci-lint-action@v9 (PR #21), but it was not found")
			}
		})

		t.Run("GoCIVersionMatchesModule", func(t *testing.T) {
			data, err := os.ReadFile(".github/workflows/go-ci.yml")
			if err != nil {
				t.Fatalf("failed to read .github/workflows/go-ci.yml: %v", err)
			}
			if !strings.Contains(string(data), "go-version-file: go.mod") {
				t.Error("expected .github/workflows/go-ci.yml to derive its Go version from go.mod")
			}
		})
	})

	// =========================================================================
	// 3.3 Security Fix Validation
	// =========================================================================
	t.Run("SecurityFixes", func(t *testing.T) {
		t.Run("GenerateSessionTokenExists", func(t *testing.T) {
			data, err := os.ReadFile("internal/handler/handlers.go")
			if err != nil {
				t.Fatalf("failed to read internal/handler/handlers.go: %v", err)
			}
			re := regexp.MustCompile(`func\s+generateSessionToken\s*\(`)
			if !re.Match(data) {
				t.Error("expected internal/handler/handlers.go to contain generateSessionToken function (HMAC-SHA256), but it was not found")
			}
		})

		t.Run("NoOldSprintfHexPattern", func(t *testing.T) {
			data, err := os.ReadFile("internal/handler/handlers.go")
			if err != nil {
				t.Fatalf("failed to read internal/handler/handlers.go: %v", err)
			}
			// Match the old insecure pattern: fmt.Sprintf("%x", ...) used for session tokens
			re := regexp.MustCompile(`fmt\.Sprintf\("%x"`)
			if re.Match(data) {
				t.Error("internal/handler/handlers.go must NOT contain the old fmt.Sprintf hex pattern for session tokens; expected HMAC-SHA256 based generateSessionToken instead")
			}
		})

		t.Run("SubtleConstantTimeCompare", func(t *testing.T) {
			data, err := os.ReadFile("internal/handler/handlers.go")
			if err != nil {
				t.Fatalf("failed to read internal/handler/handlers.go: %v", err)
			}
			if !strings.Contains(string(data), "subtle.ConstantTimeCompare") {
				t.Error("expected internal/handler/handlers.go to use subtle.ConstantTimeCompare for session validation, but it was not found")
			}
		})

		t.Run("SSLInfoVerifiedField", func(t *testing.T) {
			data, err := os.ReadFile("internal/model/types.go")
			if err != nil {
				t.Fatalf("failed to read internal/model/types.go: %v", err)
			}
			re := regexp.MustCompile(`type SSLInfo struct[\s\S]*?Verified\s+bool`)
			if !re.Match(data) {
				t.Error("expected internal/model/types.go to have Verified bool field in SSLInfo struct, but it was not found")
			}
		})

		t.Run("HTTPInfoVerifiedField", func(t *testing.T) {
			data, err := os.ReadFile("internal/model/types.go")
			if err != nil {
				t.Fatalf("failed to read internal/model/types.go: %v", err)
			}
			re := regexp.MustCompile(`type HTTPInfo struct[\s\S]*?Verified\s+bool`)
			if !re.Match(data) {
				t.Error("expected internal/model/types.go to have Verified bool field in HTTPInfo struct, but it was not found")
			}
		})
	})

	// =========================================================================
	// 3.4 Code Quality Fix Validation
	// =========================================================================
	t.Run("CodeQualityFixes", func(t *testing.T) {
		t.Run("WhoisFunctionAcceptsContext", func(t *testing.T) {
			data, err := os.ReadFile("internal/service/whois.go")
			if err != nil {
				t.Fatalf("failed to read internal/service/whois.go: %v", err)
			}
			re := regexp.MustCompile(`func\s+Whois\s*\(\s*ctx\s+context\.Context\s*,`)
			if !re.Match(data) {
				t.Error("expected internal/service/whois.go Whois function to accept context.Context parameter, but the signature was not found")
			}
		})

		t.Run("SchedulerRunMonitorJobUsesWaitGroup", func(t *testing.T) {
			data, err := os.ReadFile("internal/service/scheduler.go")
			if err != nil {
				t.Fatalf("failed to read internal/service/scheduler.go: %v", err)
			}
			content := string(data)
			hasA := strings.Contains(content, "sync.WaitGroup")
			hasB := strings.Contains(content, "sync.WaitGroup{}")
			re := regexp.MustCompile(`var\s+wg\s+sync\.WaitGroup`)
			hasC := re.MatchString(content)
			if !hasA && !hasB && !hasC {
				t.Error("expected internal/service/scheduler.go RunMonitorJob to use sync.WaitGroup, but it was not found")
			}
		})

		t.Run("TemplatesSetAndGetAllowPrivateIPs", func(t *testing.T) {
			data, err := os.ReadFile("internal/utils/templates.go")
			if err != nil {
				t.Fatalf("failed to read internal/utils/templates.go: %v", err)
			}
			content := string(data)
			if !strings.Contains(content, "func SetAllowPrivateIPs(") {
				t.Error("expected internal/utils/templates.go to have SetAllowPrivateIPs function, but it was not found")
			}
			if !strings.Contains(content, "func GetAllowPrivateIPs(") {
				t.Error("expected internal/utils/templates.go to have GetAllowPrivateIPs function, but it was not found")
			}
		})

		t.Run("TemplatesUsesSyncAtomic", func(t *testing.T) {
			data, err := os.ReadFile("internal/utils/templates.go")
			if err != nil {
				t.Fatalf("failed to read internal/utils/templates.go: %v", err)
			}
			if !strings.Contains(string(data), `"sync/atomic"`) {
				t.Error("expected internal/utils/templates.go to import sync/atomic, but the import was not found")
			}
		})

		t.Run("ConfigCORSOriginsField", func(t *testing.T) {
			data, err := os.ReadFile("internal/config/config.go")
			if err != nil {
				t.Fatalf("failed to read internal/config/config.go: %v", err)
			}
			re := regexp.MustCompile(`CORSOrigins\s+string`)
			if !re.Match(data) {
				t.Error("expected internal/config/config.go to have CORSOrigins field, but it was not found")
			}
		})

		t.Run("ConfigAllowPrivateIPsField", func(t *testing.T) {
			data, err := os.ReadFile("internal/config/config.go")
			if err != nil {
				t.Fatalf("failed to read internal/config/config.go: %v", err)
			}
			re := regexp.MustCompile(`AllowPrivateIPs\s+bool`)
			if !re.Match(data) {
				t.Error("expected internal/config/config.go to have AllowPrivateIPs field, but it was not found")
			}
		})

		t.Run("MainCallsSetAllowPrivateIPs", func(t *testing.T) {
			data, err := os.ReadFile("cmd/server/main.go")
			if err != nil {
				t.Fatalf("failed to read cmd/server/main.go: %v", err)
			}
			if !strings.Contains(string(data), "utils.SetAllowPrivateIPs") {
				t.Error("expected cmd/server/main.go to call utils.SetAllowPrivateIPs, but it was not found")
			}
		})

		t.Run("EnvExampleMaxMindLicenseKey", func(t *testing.T) {
			data, err := os.ReadFile(".env.example")
			if err != nil {
				t.Fatalf("failed to read .env.example: %v", err)
			}
			content := string(data)
			if !strings.Contains(content, "MAXMIND_LICENSE_KEY") {
				t.Error("expected .env.example to contain MAXMIND_LICENSE_KEY, but it was not found")
			}
			if strings.Contains(content, "GEOIP_LICENSE_KEY") {
				t.Error("expected .env.example to NOT contain GEOIP_LICENSE_KEY (renamed to MAXMIND_LICENSE_KEY), but it was found")
			}
		})
	})

	// =========================================================================
	// 3.5 Functional Validation
	// =========================================================================
	t.Run("FunctionalValidation", func(t *testing.T) {
		t.Run("HTTPServicePlainHTTPVerifiedFalse", func(t *testing.T) {
			allowPrivateIPs := utils.GetAllowPrivateIPs()
			utils.SetAllowPrivateIPs(true)
			defer utils.SetAllowPrivateIPs(allowPrivateIPs)
			utils.SetAllowLoopbackIPs(true)
			defer utils.SetAllowLoopbackIPs(false)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			info := service.GetHTTPInfo(context.Background(), strings.TrimPrefix(server.URL, "http://"))
			if info.Error != "" {
				t.Fatalf("plain HTTP probe failed: %s", info.Error)
			}
			if info.Verified {
				t.Error("plain HTTP connections must not be marked as TLS-verified")
			}
		})

		t.Run("SSLServiceVerifiedFieldSet", func(t *testing.T) {
			data, err := os.ReadFile("internal/service/ssl.go")
			if err != nil {
				t.Fatalf("failed to read internal/service/ssl.go: %v", err)
			}
			content := string(data)
			// The Verified field should be set based on TLS verification result.
			// Use regex to match regardless of indentation (tabs or spaces).
			re := regexp.MustCompile(`Verified:\s+verified,`)
			if !re.MatchString(content) {
				t.Error("expected internal/service/ssl.go to set Verified field based on TLS verification result, but 'Verified: verified' was not found")
			}
		})

		t.Run("SetGetAllowPrivateIPsAtomic", func(t *testing.T) {
			// Test that SetAllowPrivateIPs and GetAllowPrivateIPs work correctly
			// as atomic operations.

			// Save original value
			original := utils.GetAllowPrivateIPs()

			// Test setting to true
			utils.SetAllowPrivateIPs(true)
			if !utils.GetAllowPrivateIPs() {
				t.Error("expected GetAllowPrivateIPs() to return true after SetAllowPrivateIPs(true), got false")
			}

			// Test setting to false
			utils.SetAllowPrivateIPs(false)
			if utils.GetAllowPrivateIPs() {
				t.Error("expected GetAllowPrivateIPs() to return false after SetAllowPrivateIPs(false), got true")
			}

			// Test toggling back to true
			utils.SetAllowPrivateIPs(true)
			if !utils.GetAllowPrivateIPs() {
				t.Error("expected GetAllowPrivateIPs() to return true after SetAllowPrivateIPs(true), got false")
			}

			// Restore original value
			utils.SetAllowPrivateIPs(original)
		})
	})
}
