#!/bin/bash

set -x
set -e

oracle_git_url="https://raw.githubusercontent.com/oracle/kconfigs/refs/heads/gh-pages/out/"

kconfigs_from_oracle=(
    "Android 15 (6.6) aarch64"
    "Arch x86_64"
    "CentOS 9 Stream aarch64"
    "CentOS 9 Stream x86_64"
    "Debian 10 Buster x86_64"
    "Debian 13 Trixie aarch64"
    "Debian 13 Trixie x86_64"
    "Fedora 41 Updates aarch64"
    "Fedora 41 Updates x86_64"
    "Oracle Linux 7 (UEK 4) x86_64"
    "Oracle Linux 9 (UEK-NEXT) aarch64"
    "Oracle Linux 9 (UEK-NEXT) x86_64"
    "Ubuntu 20.04 LTS Focal x86_64"
    "Ubuntu 24.04 LTS Noble aarch64"
    "Ubuntu 24.04 LTS Noble x86_64"
)

for kconfig in "${kconfigs_from_oracle[@]}"; do
    filename="${kconfig// /_}.config" # Replace spaces with underscores
    wget -O "${filename}" "${oracle_git_url}${kconfig}/config" # Fetch kconfig
done

# Fetch some other kconfigs
wget -O Arch_hardened_x86_64.config https://gitlab.archlinux.org/archlinux/packaging/packages/linux-hardened/-/raw/main/config
wget -O Azure_Linux_x86_64.config https://raw.githubusercontent.com/microsoft/azurelinux/refs/heads/3.0/SPECS/kernel/config
wget -O OpenSUSE_x86_64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/x86_64/default
wget -O OpenSUSE_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/arm64/default
wget -O SLE-15-SP7_x86_64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/x86_64/default
wget -O SLE-15-SP7_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/arm64/default

echo "Well done!"
