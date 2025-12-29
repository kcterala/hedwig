{
  description = "Hedwig SMTP Server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            cargo
            rustc
            rustfmt
            clippy

            # Build tools
            just
            pkg-config

            # System libraries
            bzip2

            # Development tools
            docker
            docker-compose

            # Cross-compilation (optional, for Linux targets)
            cargo-cross
          ];

          shellHook = ''
            echo "Hedwig development environment loaded"
            echo "Rust version: $(rustc --version)"
            echo ""
            echo "Available commands:"
            echo "  just run       - Run the server"
            echo "  just build     - Build the project"
            echo "  just test      - Run tests"
            echo "  just dev       - Start Docker sandbox"
          '';
        };
      }
    );
}
