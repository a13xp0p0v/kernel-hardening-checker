#!/bin/sh

# SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
# SPDX-License-Identifier: GPL-3.0-only

set -x
set -e

git status
git show -s

echo "Beginning of the functional tests"

echo ">>>>> get help <<<<<"
coverage run -a --branch bin/kernel-hardening-checker
coverage run -a --branch bin/kernel-hardening-checker -h

echo ">>>>> get version <<<<<"
coverage run -a --branch bin/kernel-hardening-checker --version

echo ">>>>> print the security hardening recommendations <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m verbose
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m json

coverage run -a --branch bin/kernel-hardening-checker -p X86_32
coverage run -a --branch bin/kernel-hardening-checker -p X86_32 -m verbose
coverage run -a --branch bin/kernel-hardening-checker -p X86_32 -m json

coverage run -a --branch bin/kernel-hardening-checker -p ARM64
coverage run -a --branch bin/kernel-hardening-checker -p ARM64 -m verbose
coverage run -a --branch bin/kernel-hardening-checker -p ARM64 -m json

coverage run -a --branch bin/kernel-hardening-checker -p ARM
coverage run -a --branch bin/kernel-hardening-checker -p ARM -m verbose
coverage run -a --branch bin/kernel-hardening-checker -p ARM -m json

echo ">>>>> generate the Kconfig fragment <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64
coverage run -a --branch bin/kernel-hardening-checker -g X86_32
coverage run -a --branch bin/kernel-hardening-checker -g ARM64
coverage run -a --branch bin/kernel-hardening-checker -g ARM

echo ">>>>> try autodetection <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -a
coverage run -a --branch bin/kernel-hardening-checker -a -m verbose
coverage run -a --branch bin/kernel-hardening-checker -a -m json
coverage run -a --branch bin/kernel-hardening-checker -a -m show_ok
coverage run -a --branch bin/kernel-hardening-checker -a -m show_fail

echo ">>>>> check the example kconfig files, cmdline, and sysctl <<<<<"
cat /proc/cmdline
echo "l1tf=off mds=full mitigations=off randomize_kstack_offset=on retbleed=0 iommu.passthrough=0" > ./cmdline_example
cat ./cmdline_example
sysctl -a > /tmp/sysctls
CONFIG_DIR=`find . -name config_files`
SYSCTL_EXAMPLE=$CONFIG_DIR/distros/example_sysctls.txt
KCONFIGS=`find $CONFIG_DIR -type f | grep -e "\.config" -e "\.gz"`
COUNT=0
for C in $KCONFIGS
do
        COUNT=$(expr $COUNT + 1)
        echo "\n>>>>> checking kconfig number $COUNT <<<<<"
        coverage run -a --branch bin/kernel-hardening-checker -c $C
        coverage run -a --branch bin/kernel-hardening-checker -c $C -m verbose > /dev/null
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l /proc/cmdline
        coverage run -a --branch bin/kernel-hardening-checker -c $C -s /tmp/sysctls
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m verbose > /dev/null
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m json
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m show_ok
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m show_fail
done
echo "\n>>>>> have checked $COUNT kconfigs <<<<<"

echo ">>>>> test kconfig arch detection <<<<<"
cp $CONFIG_DIR/defconfigs/x86_64_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected microarchitecture: X86_64"
cp $CONFIG_DIR/defconfigs/x86_32_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected microarchitecture: X86_32"
cp $CONFIG_DIR/defconfigs/arm_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected microarchitecture: ARM"
cp $CONFIG_DIR/defconfigs/arm64_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected microarchitecture: ARM64"

echo ">>>>> test sysctl arch detection <<<<<"
echo "kernel.arch = x86_64" > /tmp/sysctl_arch # same as output of `sysctl kernel.arch`
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected microarchitecture: X86_64"
echo "kernel.arch = i386" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected microarchitecture: X86_32"
echo "kernel.arch = armv7l" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected microarchitecture: ARM"
echo "kernel.arch = aarch64" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected microarchitecture: ARM64"
echo "kernel.arch = armv8b" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected microarchitecture: ARM64"
echo "kernel.arch = bad" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "bad is an unsupported arch, arch-dependent checks will be dropped"

echo ">>>>> check sysctl separately <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m verbose > /dev/null
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m json
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m show_ok
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m show_fail

echo ">>>>> check sysctl.conf (it should not fail) <<<<<"
cat /etc/sysctl.conf
coverage run -a --branch bin/kernel-hardening-checker -s /etc/sysctl.conf

echo ">>>>> test -v (kernel version detection) <<<<<"
cp kernel_hardening_checker/config_files/distros/fedora_34.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config -v /proc/version

echo "Collect coverage for error handling"

echo ">>>>> -c and -p together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -c ./test.config && exit 1

echo ">>>>> -c and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -c ./test.config && exit 1

echo ">>>>> -l without -c <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -l /proc/cmdline && exit 1

echo ">>>>> -s and -p together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -s $SYSCTL_EXAMPLE && exit 1

echo ">>>>> -s and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -s $SYSCTL_EXAMPLE && exit 1

echo ">>>>> -p and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -g X86_64 && exit 1

echo ">>>>> wrong modes for -p <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m show_ok && exit 1
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m show_fail && exit 1

echo ">>>>> wrong mode for -g <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -m show_ok && exit 1

echo ">>>>> no kconfig file <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -c ./nosuchfile && exit 1

echo ">>>>> no kernel version <<<<<"
sed '3d' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> strange kernel version in kconfig <<<<<"
sed '3 s/5./version 5./' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> strange kernel version via -v <<<<<"
sed '3d' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config -v /proc/cmdline && exit 1

echo ">>>>> no arch <<<<<"
sed '305d' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> more than one arch <<<<<"
cp test.config error.config
echo 'CONFIG_ARM64=y' >> error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> invalid enabled kconfig option <<<<<"
cp test.config error.config
echo 'CONFIG_FOO=is not set' >> error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> kconfig option without a value (should emit a warning) <<<<<"
cp test.config error.config
echo 'CONFIG_FOO=' >> error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config | grep "WARNING: found strange Kconfig option CONFIG_FOO with empty value"

echo ">>>>> one config option multiple times <<<<<"
cp test.config error.config
echo 'CONFIG_BUG=y' >> error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> invalid compiler versions <<<<<"
cp test.config error.config
sed '8 s/CONFIG_CLANG_VERSION=0/CONFIG_CLANG_VERSION=120000/' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> unexpected line in the kconfig file <<<<<"
cp test.config error.config
echo 'some strange line' >> error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> no cmdline file <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config -l ./nosuchfile && exit 1

echo ">>>>> empty cmdline file <<<<<"
touch ./empty_file
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config -l ./empty_file && exit 1

echo ">>>>> multi-line cmdline file <<<<<"
echo 'hey man 1' > cmdline
echo 'hey man 2' >> cmdline
coverage run -a --branch bin/kernel-hardening-checker -c test.config -l cmdline && exit 1

echo ">>>>> no sysctl file <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -s ./nosuchfile && exit 1

echo ">>>>> empty sysctl file <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -c test.config -s empty_file && exit 1

echo ">>>>> unexpected line in the sysctl file <<<<<"
cp $SYSCTL_EXAMPLE error_sysctls
echo 'some strange line' >> error_sysctls
coverage run -a --branch bin/kernel-hardening-checker -c test.config -s error_sysctls && exit 1

echo "The end of the functional tests"
