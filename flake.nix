{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    fenix,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.stable.withComponents ["cargo" "rustc" "rustfmt" "clippy"];
      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };
      python = pkgs.python3.withPackages (p: [p.fido2]);
      helper = pkgs.writeShellApplication {
        name = "rbw-passkey";
        text = ''exec ${python}/bin/python3 ${./bin/rbw-passkey} "$@"'';
      };
      rbw = rustPlatform.buildRustPackage {
        pname = "rbw";
        version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
        src = pkgs.lib.cleanSource ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [pkgs.makeWrapper];
        postInstall = ''
          wrapProgram $out/bin/rbw-agent --prefix PATH : ${pkgs.lib.makeBinPath [helper pkgs.pinentry-qt]}
          wrapProgram $out/bin/rbw --set-default RBW_AGENT $out/bin/rbw-agent
        '';
        doCheck = false;
      };
    in {
      packages = {
        default = rbw;
        passkey-helper = helper;
        launcher = pkgs.writeShellApplication {
          name = "vaultwarden-menu";
          runtimeInputs = [rbw (pkgs.rofi-rbw.override {inherit rbw;}) pkgs.rofi pkgs.wl-clipboard pkgs.wtype];
          text = ''exec rofi-rbw "$@"'';
        };
      };
      devShells.default = pkgs.mkShell {
        packages = [toolchain python helper pkgs.just pkgs.alejandra pkgs.pkg-config pkgs.pinentry-qt];
      };
      formatter = pkgs.alejandra;
    });
}
