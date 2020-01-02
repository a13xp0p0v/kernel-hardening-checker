{ pkgs ? (import <nixpkgs> {}) }:
with pkgs;

pkgs.python3.pkgs.buildPythonPackage {
  name = "kconfig-hardend-check";
  src = ./.;
  SOURCE_DATE_EPOCH = "1523278946";
}
