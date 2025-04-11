{
  description = "PlayStation 1 emulator and debugger";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    nix-github-actions.url = "github:nix-community/nix-github-actions";
    nix-github-actions.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    nix-github-actions
  }:
  let
    lib = nixpkgs.lib;
    # githubSystems = builtins.attrNames nix-github-actions.lib.githubPlatforms;
    # forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    # forGithubSystems = lib.genAttrs githubSystems;
    # TODO: githubSystems should be supportedSystems intersects lib.githubPlatforms
    # Some of the dependencies don't build on clang. Will fix later
    supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    forAllSystems = lib.genAttrs supportedSystems;
    forGithubSystems = lib.genAttrs supportedSystems;
  in {
    packages = forAllSystems (system:
    let 
      pkgs = nixpkgs.legacyPackages.${system};
      cross = import nixpkgs {
        inherit system;
        crossSystem = "mipsel-none-elf";
      };
    in {
      default = self.packages.${system}.pcsx-redux;

      pcsx-redux = pkgs.callPackage ./pcsx-redux.nix {
          src = self;
          platforms = lib.systems.flakeExposed;
          gccMips = cross.buildPackages.gccWithoutTargetLibc;
      };
    });

    githubActions = nix-github-actions.lib.mkGithubMatrix {
      checks = forGithubSystems (system: 
        # Prevent double build
        builtins.removeAttrs self.packages.${system} ["default"]
      );
    };
  };
}
