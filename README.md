This program, written in Go, contains a collection of tools to generate key pairs in PEM files, sign files, and verify signatures.

Usage

Run it:

brave_signer COMMAND FLAGS

Available commands (check documentation to learn about all supported settings):

    keys generate [--pub-key-path pub_key.pem] [--priv-key-path priv_key.pem] — generate an RSA key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with Argon2 key derivation function is utilized.

