{ pkgs ? import <nixpkgs> {}
}:
with pkgs;
stdenv.mkDerivation {
  name = "kconf";
  nativeBuildInputs = [
    linuxPackages_hardened.kernel
    linuxPackages_latest.kernel
    linuxPackages.kernel
  ];

  dontUnpack = true;
  dontInstall = true;

  buildPhase = ''
    mkdir  $out

    mkdir $out/linuxPackages_hardened/
    cp ${pkgs.linuxPackages_hardened.kernel.configfile} $out/linuxPackages_hardened/kernel.conf
    echo ${pkgs.linuxPackages_hardened.kernel.version} > $out/linuxPackages_hardened/kernel.version

    mkdir $out/linuxPackages_latest/
    cp ${pkgs.linuxPackages_latest.kernel.configfile} $out/linuxPackages_latest/kernel.conf
    echo ${pkgs.linuxPackages_latest.kernel.version} > $out/linuxPackages_latest/kernel.version

    mkdir $out/linuxPackages_lts/
    cp ${pkgs.linuxPackages.kernel.configfile} $out/linuxPackages_lts/kernel.conf
    echo ${pkgs.linuxPackages.kernel.version} > $out/linuxPackages_lts/kernel.version
    '';

  
}
