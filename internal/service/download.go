package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func writeFileAtomically(path string, source io.Reader, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("invalid download limit")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	written, copyErr := io.Copy(temporary, io.LimitReader(source, maxBytes+1))
	if copyErr == nil && written > maxBytes {
		copyErr = fmt.Errorf("download exceeds %d-byte limit", maxBytes)
	}
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	if closeErr := temporary.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return copyErr
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	return nil
}
