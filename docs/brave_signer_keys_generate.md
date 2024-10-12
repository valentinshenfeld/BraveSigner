## brave_signer keys generate

Generates an Ed25519 key pair.

### Synopsis

Generate an Ed25519 key pair and store it in PEM files. The private key will be encrypted using a passphrase that you'll need to enter. AES encryption with the Argon2 key derivation function is utilized for strong security.

The following files will be created:
- A private key file (encrypted) in PEM format.
- A public key file in PEM format.


```
brave_signer keys generate [flags]
```

### Options

```
      --argon2-key-len uint32     Length of the derived key (in bytes) for the Argon2id key derivation function (default 32)
      --argon2-memory uint32      Memory parameter (in megabytes) for the Argon2id key derivation function (default 64)
      --argon2-threads uint8      Number of threads used in the Argon2id key derivation function (default 4)
      --argon2-time uint32        Time parameter for the Argon2id key derivation function (default 1)
  -h, --help                      help for generate
      --priv-key-path string      Path to save the private key in PEM format (default "priv_key.pem")
      --pub-key-path string       Path to save the public key in PEM format (default "pub_key.pem")
      --salt-size int             Salt size (in bytes) used in the Argon2 key derivation process (default 16)
      --skip-pem-presence-check   Skip checking if private and/or public keys already exist. Setting this option to true might result in overwriting your existing key pair
```

### Options inherited from parent commands

```
      --config-file-name string   Your config file name. (default "config")
      --config-file-type string   Your config file type. (default "yaml")
      --config-path string        Config file location. (default ".")
```

### SEE ALSO

* [brave_signer keys](brave_signer_keys.md)	 - Manage key pairs.

###### Auto generated by spf13/cobra on 17-Sep-2024