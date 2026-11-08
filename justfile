fmt:
    cargo fmt --all
    alejandra flake.nix

fmt-check:
    cargo fmt --all -- --check
    alejandra --check flake.nix

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --all-features passkey
    python -m unittest discover -s tests -p 'test_passkey*.py'

check: fmt-check clippy test

build:
    cargo build --release --bins

menu:
    nix run .#launcher
