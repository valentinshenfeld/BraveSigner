package utils

import (
	"BraveSigner/logger"
	"errors"
	"fmt"
	"golang.org/x/term"
	"io/fs"
	"os"
	"path/filepath"
)

func ProcessFilePath(path string) (string, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("converting to absolute path: %v", err)
	}

	pathInfo, err := CheckPathInfo(absolutePath)
	if err != nil {
		return "", err
	}
	if pathInfo == nil {
		return "", fmt.Errorf("path '%s' does not exist", path)
	}
	if pathInfo.IsDir() {
		return "", fmt.Errorf("path '%s' is a directory, not a file", path)
	}

	return absolutePath, nil
}

// CheckFileExists checks if a file exists at the given path
func CheckPathInfo(path string) (fs.FileInfo, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching file info: %v", err)
	}

	return fileInfo, nil
}

// GetPassphrase prompts the user for a passphrase and securely reads it.
func GetPassphrase() ([]byte, error) {
	fmt.Println("Enter passphrase:")

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}
	defer safeRestore(int(os.Stdin.Fd()), oldState)

	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	return passphrase, nil
}

// safeRestore attempts to restore the terminal to its original state and logs an error if it fails.
func safeRestore(fd int, state *term.State) {
	if err := term.Restore(fd, state); err != nil {
		logger.HaltOnErr(fmt.Errorf("failed to restore terminal state: %v", err), "Terminal restoration failed")
	}
}
