package main

import (
	"BraveSigner/cmd"
	"BraveSigner/logger"
	"errors"
)

func main() {

	rootCmd := cmd.RootCmd()
	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnErr(errors.New("cannot proceed, exiting now"), "Initial setup failed")
	}
}
