# rbw passkey fork

This fork adds passkey login and local vault unlock to upstream rbw. Keep
password authentication available and preserve upstream CLI compatibility.

- `src/passkey.rs`: WebAuthn models, PRF key derivation, and helper protocol.
- `bin/rbw-passkey`: USB authenticator access through Yubico's python-fido2.
- `src/bin/rbw-agent/actions.rs`: authentication, encrypted cache, and agent keys.
- `flake.nix`: reproducible rbw, helper, and rofi-rbw launcher packages.

Use `direnv exec . just check` for formatting, lint, type checks, and focused
passkey tests. `just build` builds both binaries. Never log PINs, PRF outputs,
tokens, private keys, or decrypted vault contents. Cache only encrypted key
material; drop decrypted keys on lock and timeout. Hardware tests require the
user to enter the PIN directly into pinentry and touch the authenticator.

Keep machine-specific server URLs, email, and local configuration out of git.
