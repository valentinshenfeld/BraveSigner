package cmd

import (
	"BraveSigner/cmd/keys"
	"BraveSigner/cmd/signatures"
	"BraveSigner/config"
	"BraveSigner/logger"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var version = "dev" // default version, can be overridden at build time

func RootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "brave_signer",
		Short: "Bravely generate key pairs, sign files, and verify signatures.",
		Long: `brave_signer is a comprehensive toolset for cryptographic operations, including generating Ed25519 key pairs, signing files, and verifying signatures. 
	
	Features:
	- Generate secure Ed25519 key pairs and store them in PEM files.
	- Encrypt private keys using AES with Argon2 key derivation.
	- Sign files and create .sig files containing the signature and signer information.
	- Verify file signatures to ensure authenticity and integrity.
	`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initializeConfig(cmd, config.ConfigParams{
				Name: cmd.Flag("config-file-name").Value.String(),
				Type: cmd.Flag("config-file-type").Value.String(),
				Path: cmd.Flag("config-path").Value.String(),
			})
		},
	}

	rootCmd.PersistentFlags().String("config-file-name", "config", "Your config file name.")
	rootCmd.PersistentFlags().String("config-file-type", "yaml", "Your config file type.")
	rootCmd.PersistentFlags().String("config-path", ".", "Config file location.")

	// Add subcommands
	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of brave_signer",
		Long:  `All software has versions. This is brave_signer's version.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("brave_signer version:", version)
		},
	})

	// Add hidden docs command
	rootCmd.AddCommand(&cobra.Command{
		Use:    "gendocs",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateDocs(rootCmd, "./docs"); err != nil {
				logger.Warn(fmt.Errorf("error generating docs: %v", err))
			}
		},
	})

	return rootCmd
}

func initializeConfig(cmd *cobra.Command, params config.ConfigParams) error {
	localViper, err := config.LoadFromFile(params)
	if err != nil {
		return err
	}

	if err := config.BindFlags(cmd, localViper); err != nil {
		return err
	}

	ctx := context.WithValue(cmd.Context(), config.ViperKey, localViper)
	cmd.SetContext(ctx)
	return nil
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	// Ensure the base directory exists
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Generate markdown documentation for all commands
	return doc.GenMarkdownTree(rootCmd, dir)
}
