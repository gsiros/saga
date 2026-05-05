{
  description = "on god, the saga-fm flake";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... } @ inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname   = "saga-fm";
          name   = "saga-fm";
          src     = ./.;
        };

        devShells.default = pkgs.mkShellNoCC rec {
          buildInputs = with pkgs; [
            proverif
            verifpal
          ];

          shellHook = ''
            echo "Switching to saga-fm dev-shell... :D"
            # this=$$
            # parent=$(ps -o ppid= -p "$this" | tr -d ' ')
            # orig_shell=$(ps -p "$parent" -o comm= | tr -d ' ')
            # case "$orig_shell" in
              # nix|nix-shell|nix|bash|zsh|fish|dash) : ;;     
              # *)
                # orig_shell="/bin/bash"
            # esac

            # echo "Switching to $(basename "$orig_shell") inside saga dev-shell..."
            # exec "$orig_shell" -l # login mode
          '';
        };
      }
    );
}
