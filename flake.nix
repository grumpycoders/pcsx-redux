{
  description = "";

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
    # Some of the dependencies don't build on aarch64. Will fix later
    supportedSystems = [ "x86_64-linux" "x86_64-darwin" ];
    forAllSystems = lib.genAttrs supportedSystems;
    forGithubSystems = lib.genAttrs supportedSystems;
  in {
    packages = forAllSystems (system:
      let pkgs = import nixpkgs { inherit system; };
    in {
      pcsx-redux = pkgs.callPackage ./pcsx-redux.nix {
          src = self;
          platforms = lib.systems.flakeExposed;
      };
      # FIXME: default gets duplicated in githubActions
      # default = self.packages.${system}.pcsx-redux;
    });

    githubActions = nix-github-actions.lib.mkGithubMatrix {
      checks = forGithubSystems (system: self.packages.${system});
    };
  };
}
