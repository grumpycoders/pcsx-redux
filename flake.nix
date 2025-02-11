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
    ignorePaths = [
      # ".github"
      # ".gitignore"
      # "flake.nix"
      # "flake.lock"
      # "pcsx-redux.nix"
    ];
    # TODO: do all platforms
    pkgs = import nixpkgs { system = "x86_64-linux"; };
  in
  {
    githubActions = nix-github-actions.lib.mkGithubMatrix {

      checks = self.packages;
    };
    packages."x86_64-linux" = {
      # TODO: debug should be another output not another derivation
      pcsx-redux = pkgs.callPackage ./pcsx-redux.nix { src = self; };
  };
}
