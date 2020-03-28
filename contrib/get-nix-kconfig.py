#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python3

import json
import os
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


def main() -> None:
    proc = subprocess.run(
        ["nix", "search", "-u", "--json", "^nixpkgs.linux_"], capture_output=True
    )
    data = json.loads(proc.stdout)
    with TemporaryDirectory() as temp:
        for pkg in data.keys():
            symlink = os.path.join(temp, pkg)
            res = subprocess.run(["nix", "build", f"{pkg}.configfile", "-o", symlink])
            if res.returncode != 0:
                print(f"failed to get configuration for {pkg}", file=sys.stderr)
                continue
            name = f"{pkg.replace('.', '-')}-config"
            with open(name, "w") as dst, open(symlink) as src:
                shutil.copyfileobj(src, dst)


if __name__ == "__main__":
    main()
