package signatures

import (
	"BraveSigner/config"
	"BraveSigner/crypto_utils"
	"BraveSigner/logger"
	"BraveSigner/utils"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

type PkLoadConfig struct {
	pkPath       string
	time         uint32
	memory       uint32
	threads      uint8
	argon2KeyLen uint32
}

func init() {
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	signaturesSignFileCmd.Flags().String("priv-key-path", "priv_key.pem", "Path to your Ed25519 private key in PEM format")
	signaturesSignFileCmd.Flags().String("signer-id", "", "Signer's name or identifier")
	signaturesSignFileCmd.Flags().Uint32("argon2-time", 1, "Time parameter used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("argon2-memory", 64, "Memory parameter (in megabytes) used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint8("argon2-threads", 4, "Number of threads used in the Argon2id key derivation function")
	signaturesSignFileCmd.Flags().Uint32("argon2-key-len", 32, "Length of the derived key (in bytes) for the Argon2id key derivation function")
}

func validateSignerID(signerID string) error {
	const (
		minSignerInfoLength = 1
		maxSignerInfoLength = 65535
	)

	if len(signerID) < minSignerInfoLength || len(signerID) > maxSignerInfoLength {
		return fmt.Errorf("signer information must be between %d and %d characters", minSignerInfoLength, maxSignerInfoLength)
	}
	return nil
}

var signaturesSignFileCmd = &cobra.Command{
	Use:   "signfile",
	Short: "Sign the file.",
	Long: `Sign the specified file using an Ed25519 private key and store the signature inside a .sig file named after the original file. You'll be asked for a passphrase to decrypt the private key.

The process involves:
1. Loading and decrypting the Ed25519 private key.
2. Hashing the file using the specified hash algorithm.
3. Signing the hash of the file.
4. Storing the signature along with the signer information in a .sig file located in the same directory as the original file.
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		signerID := cmd.Flag("signer-id").Value.String()
		return validateSignerID(signerID)
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("Starting signing process...")

		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		logger.Info("Loading private key...")

		fullPrivKeyPath, err := utils.ProcessFilePath(localViper.GetString("priv-key-path"))
		logger.HaltOnErr(err, "failed to process priv key path")

		privateKey, err := loadPrivateKey(PkLoadConfig{
			pkPath:       fullPrivKeyPath,
			time:         localViper.GetUint32("argon2-time"),
			memory:       localViper.GetUint32("argon2-memory"),
			threads:      uint8(localViper.GetUint("argon2-threads")),
			argon2KeyLen: localViper.GetUint32("argon2-key-len"),
		})
		logger.HaltOnErr(err, "cannot load priv key from file")

		logger.Info("Hashing the file...")

		fullFilePath, err := utils.ProcessFilePath(localViper.GetString("file-path"))
		logger.HaltOnErr(err, "failed to process file path")

		hashAlgo := localViper.GetString("hash-algo")
		hasher, _ := getHashFunction(hashAlgo)

		digest, err := hashFile(fullFilePath, hasher)
		logger.HaltOnErr(err, "cannot hash the file")

		logger.Info("Signing the file...")

		signature := signMessage(digest, privateKey)

		signaturePackage, err := makeSignaturePackage(signature, localViper.GetString("signer-id"))
		logger.HaltOnErr(err, "cannot make signature package")

		fullSigPath, err := writeSignatureToFile(signaturePackage, fullFilePath)
		logger.HaltOnErr(err, "cannot write signature to file")

		logger.Info(fmt.Sprintf("Signature generation successful for file: %s\n", filepath.Base(fullFilePath)))
		logger.Info(fmt.Sprintf(".sig file created at: %s\n", fullSigPath))
	},
}

func makeSignaturePackage(signature []byte, signerInfo string) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfo))); err != nil {
		return nil, fmt.Errorf("failed to write signer info length: %v", err)
	}

	if _, err := buf.WriteString(signerInfo); err != nil {
		return nil, fmt.Errorf("failed to write signer info: %v", err)
	}

	if _, err := buf.Write(signature); err != nil {
		return nil, fmt.Errorf("failed to write signature: %v", err)
	}

	return buf.Bytes(), nil
}

func writeSignatureToFile(signaturePackage []byte, initialFilePath string) (string, error) {
	sigFilePath := filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")

	if err := os.WriteFile(sigFilePath, signaturePackage, 0o644); err != nil {
		return "", err
	}

	return sigFilePath, nil
}

func signMessage(message []byte, privateKey ed25519.PrivateKey) []byte {
	signature := ed25519.Sign(privateKey, message)
	return signature
}

func decodePEMFile(pkPath string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %v", err)
	}

	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM file: extra data encountered after PEM block")
	}

	return block, nil
}

func getSaltAndNonce(block *pem.Block) ([]byte, []byte, error) {
	nonceB64, ok := block.Headers["Nonce"]
	if !ok {
		return nil, nil, fmt.Errorf("nonce not found in PEM headers")
	}
	saltB64, ok := block.Headers["Salt"]
	if !ok {
		return nil, nil, fmt.Errorf("salt not found in PEM headers")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %v", err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %v", err)
	}

	return nonce, salt, nil
}

func loadPrivateKey(config PkLoadConfig) (ed25519.PrivateKey, error) {
	block, err := decodePEMFile(config.pkPath)
	if err != nil {
		return nil, err
	}

	nonce, salt, err := getSaltAndNonce(block)
	if err != nil {
		return nil, err
	}

	passphrase, err := utils.GetPassphrase()
	if err != nil {
		return nil, err
	}

	// Derive the key from the passphrase and salt
	key, err := crypto_utils.DeriveKey(crypto_utils.KeyDerivationConfig{
		Passphrase: passphrase,
		Salt:       salt,
		Time:       config.time,
		Memory:     config.memory,
		KeyLen:     config.argon2KeyLen,
		Threads:    config.threads,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %v", err)
	}

	crypter, err := crypto_utils.MakeCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to make crypter: %v", err)
	}

	// Decrypt the private key
	plaintext, err := crypter.Open(nil, []byte(nonce), block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("private key file decryption failed: %v", err)
	}

	// Parse the Ed25519 private key
	privateKey := ed25519.PrivateKey(plaintext)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	return privateKey, nil
}
