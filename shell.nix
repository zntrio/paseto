{ pkgs ? import <nixpkgs> { } }:

with pkgs;

mkShell {
  buildInputs = [
    go_1_21
    gotools
    gopls
    go-outline
    gocode
    gopkgs
    gocode-gomod
    godef
    golint
    delve
    golangci-lint
  ];
}
