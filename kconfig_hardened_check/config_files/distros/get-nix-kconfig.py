#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python3

import json
import os
import shutil
import subprocess
import sys
import glob
from tempfile import TemporaryDirectory
from pathlib import Path


def main() -> None:
    root = Path(__file__).parent.resolve()
    proc = subprocess.run(
        ["nix", "search", "nixpkgs", "--json", "linuxKernel.packages.linux_.*\.kernel"],
        stdout=subprocess.PIPE,
        check=True,
    )
    data = json.loads(proc.stdout)
    print("Found kernels:")
    for kernel in data.keys():
        print(kernel)
    current_kernels = set(glob.glob(str(root / "nixpkgs-linux_*-config")))
    with TemporaryDirectory() as temp:
        for pkg in data.keys():
            symlink = os.path.join(temp, pkg)
            res = subprocess.run(["nix", "build", f"nixpkgs#{pkg}.configfile", "-o", symlink])
            if res.returncode != 0:
                print(f"failed to get configuration for {pkg}", file=sys.stderr)
                continue
            print(pkg)
            name = pkg.replace(".kernel", "")
            name = name.replace("legacyPackages.x86_64-linux.linuxKernel.packages.", "nixpkgs-")
            dst_path = str(root / f"{name}.config")
            with open(dst_path, "w") as dst, open(symlink) as src:
                shutil.copyfileobj(src, dst)
            if dst_path in current_kernels:
                current_kernels.remove(dst_path)
    if current_kernels:
        print("cleanup old kernels")
    for kernel in current_kernels:
        print(kernel)
        os.remove(kernel)


if __name__ == "__main__":
    main()
