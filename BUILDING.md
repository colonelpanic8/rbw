# Passkey fork

Build and check with Nix:

```sh
direnv allow
direnv exec . just check
nix build .#launcher -o result-launcher
```

The launcher uses this fork of rbw, including its agent and USB passkey helper.
The helper uses Yubico's python-fido2 for WebAuthn, user verification, and PRF.
It receives the PIN over a private pipe and returns the assertion and PRF
result over another pipe. The PRF result is removed from the assertion before
the assertion is submitted to the server. Neither the PIN nor PRF result is
persisted.

Configure the client before logging in:

```sh
nix run . -- config set email you@example.com
nix run . -- config set base_url https://vault.example.com
nix run . -- config set login_method passkey
nix run . -- config set pinentry pinentry-qt
nix run . -- login
```

The passkey must already have vault encryption enabled in the web vault.
Connect one security key, enter its PIN in pinentry, and touch it when it
flashes. Keys that verify the user themselves (a fingerprint, or a watch's own
screen lock) and have no client PIN skip the pinentry prompt. No master password is needed for passkey login or subsequent local
unlocks. The encrypted cache contains the credential ID and encrypted key
material; locking drops the decrypted keys from the agent. Local unlock can
work offline. Sync refreshes the encrypted key material and removes the local
unlock option if the server no longer advertises that credential.

The helper currently requires exactly one matching credential. Password login
remains available with `rbw config set login_method password`. WebAuthn 2FA is
separate and remains unsupported by upstream rbw's password-login path.

Run the launcher with:

```sh
nix run .#launcher
```

Configure rofi-rbw in `$XDG_CONFIG_HOME/rofi-rbw.rc`, for example:

```ini
selector=rofi
action=copy
clear-after=30
```

See upstream rofi-rbw for username/password typing shortcuts and per-entry
`_autotype` fields. The initial copy action avoids typing into an unintended
focused window.
