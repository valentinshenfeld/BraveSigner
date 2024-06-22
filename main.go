package main

import (
	"BraveSigner/cmd"
	"BraveSigner/cmd/keys"
	"BraveSigner/cmd/signatures"
	"BraveSigner/logger"
)

func main() {
	rootCmd := cmd.RootCmd()
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.HaltOnErr(err, "Initial setup failed")
	}

}
