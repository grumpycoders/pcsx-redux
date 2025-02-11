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
    nix-github-actions,
    ...
  }:
  let
    lib = nixpkgs.lib;
    forAllSystems = lib.genAttrs lib.systems.flakeExposed;
  in {
    packages = forAllSystems (system:
      let pkgs = { inherit system; };
    in {
      pcsx-redux = pkgs.callPackage ./pcsx-redux.nix { src = self; };
      default = self.packages.${system}.pcsx-redux;
    });

    githubActions = nix-github-actions.lib.mkGithubMatrix {
      checks = forAllSystems self.packages;
    };
}
