{
  description = "CrabEFI - A minimal UEFI implementation as a coreboot payload";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      overlays = [ (import rust-overlay) ];
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs [
          "x86_64-linux"
          "aarch64-linux"
        ] (system: function (import nixpkgs { inherit system overlays; }));
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # QEMU for testing
            qemu

            # Disk image tools
            parted
            mtools
            dosfstools

            # coreboot tools for adding payload
            coreboot-utils

            # Compression for firmware
            zstd

            # Rust
            (rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
          ];
        };
      });
    };
}
