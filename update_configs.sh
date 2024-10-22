#!/bin/bash

remove=false
if [[ "$1" == "-r" ]]; then # option to remove all created configs
    remove=true
fi

if ! git clone --branch gh-pages https://github.com/oracle/kconfigs; then
    echo "Failed to clone kconfigs. Make sure the "kconfigs" directory does not exist or empty."
    exit 1
fi

for dir in kconfigs/out/*/; do
    config_file="${dir}config"
    cleaning_stage_1=$(echo "$dir" | tr -d "\"'") # clean unneeded quotes
    cleaning_stage_2=$(echo ${cleaning_stage_1// /_}) # change " " to the "_"
    filename=$(basename "$cleaning_stage_2") # extract file name
    target="kernel_hardening_checker/config_files/distros/${filename}.config"

    if [[ "$remove" == true ]]; then
        rm "${target}"
    else
        cp "$config_file" "${target}"
    fi

done

rm -rf kconfigs # clean unneeded folder

if [[ "$remove" == true ]]; then
    rm kernel_hardening_checker/config_files/distros/Clearlinux_*
    rm kernel_hardening_checker/config_files/distros/OpenSUSE_*
    rm kernel_hardening_checker/config_files/distros/SLE-15-SP7_*
    rm kernel_hardening_checker/config_files/distros/Azure_linux_*
    exit 1
fi

# fetch some other kconfigs
wget -O kernel_hardening_checker/config_files/distros/Clearlinux_x86-64.config https://raw.githubusercontent.com/clearlinux-pkgs/linux/master/config
wget -O kernel_hardening_checker/config_files/distros/Clearlinux_x86-64.cmdline https://raw.githubusercontent.com/clearlinux-pkgs/linux/master/cmdline
wget -O kernel_hardening_checker/config_files/distros/OpenSUSE_x86-64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/x86_64/default
wget -O kernel_hardening_checker/config_files/distros/OpenSUSE_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/master/config/arm64/default
wget -O kernel_hardening_checker/config_files/distros/SLE-15-SP7_x86-64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/x86_64/default
wget -O kernel_hardening_checker/config_files/distros/SLE-15-SP7_aarch64.config https://raw.githubusercontent.com/openSUSE/kernel-source/refs/heads/SLE15-SP7/config/x86_64/default
wget -O kernel_hardening_checker/config_files/distros/Azure_linux_x86_64.config https://raw.githubusercontent.com/microsoft/azurelinux/refs/heads/1.0/SPECS/kernel/config
