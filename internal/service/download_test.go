package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.dat")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomically(path, bytes.NewBufferString("new data"), 32); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new data" {
		t.Fatalf("replacement content = %q", content)
	}
}

func TestWriteFileAtomicallyFailurePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.dat")
	if err := os.WriteFile(path, []byte("known good"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeFileAtomically(path, bytes.NewBufferString("oversized"), 4); err == nil {
		t.Fatal("expected oversized update to fail")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "known good" {
		t.Fatalf("failed update replaced live file with %q", content)
	}
}

type failingDownloadReader struct{}

func (failingDownloadReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestWriteFileAtomicallyReadErrorPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.dat")
	if err := os.WriteFile(path, []byte("known good"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomically(path, failingDownloadReader{}, 32); err == nil {
		t.Fatal("expected read failure")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "known good" {
		t.Fatalf("failed update replaced live file with %q", content)
	}
}
