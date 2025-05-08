#!/bin/bash

set -x
set -e

oracle_git_url="https://raw.githubusercontent.com/oracle/kconfigs/refs/heads/gh-pages/"

readarray -t kconfigs_from_oracle < <(
  # wget output could alternatively be piped to jq -r '.distros[].unique_name'
  wget -qO- "${oracle_git_url}docs/summary.json" | grep -o '"unique_name": "[^"]*"' |  awk -F'"' '{print $4}'
)

for kconfig in "${kconfigs_from_oracle[@]}"; do
    filename="${kconfig// /_}.config" # Replace spaces with underscores
    wget -O "${filename}" "${oracle_git_url}out/${kconfig}/config" # Fetch kconfig
done

# Fetch some other kconfigs
wget -O Arch_hardened_x86_64.config https://gitlab.archlinux.org/archlinux/packaging/packages/linux-hardened/-/raw/main/config
wget -O Azure_Linux_x86_64.config https://raw.githubusercontent.com/microsoft/azurelinux/refs/heads/3.0/SPECS/kernel/config
wget -O OpenSUSE_x86_64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/x86_64/default
wget -O OpenSUSE_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/arm64/default
wget -O OpenSUSE_riscv64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/riscv64/default
wget -O SLE-15-SP7_x86_64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/x86_64/default
wget -O SLE-15-SP7_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/arm64/default

echo "Well done!"
