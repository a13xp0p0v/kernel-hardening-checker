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

coverage run -a --branch bin/kernel-hardening-checker -p RISCV
coverage run -a --branch bin/kernel-hardening-checker -p RISCV -m verbose
coverage run -a --branch bin/kernel-hardening-checker -p RISCV -m json

echo ">>>>> generate the Kconfig fragment <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64
coverage run -a --branch bin/kernel-hardening-checker -g X86_32
coverage run -a --branch bin/kernel-hardening-checker -g ARM64
coverage run -a --branch bin/kernel-hardening-checker -g ARM
coverage run -a --branch bin/kernel-hardening-checker -g RISCV

echo ">>>>> test the autodetection mode <<<<<"
cat /proc/cmdline
cat /proc/version
ls -l /boot
ls -l /proc/c*
FILE1=/proc/config.gz
FILE2=/boot/config-`uname -r`
if [ ! -f "$FILE1" ] ; then
    echo "$FILE1 does not exist"
    if [ ! -f "$FILE2" ] ; then
        echo "$FILE2 does not exist, create it"
        cp kernel_hardening_checker/config_files/distros/Arch_x86_64.config "$FILE2"
    fi
fi
ls -l /boot
coverage run -a --branch bin/kernel-hardening-checker -a
coverage run -a --branch bin/kernel-hardening-checker -a -m verbose
coverage run -a --branch bin/kernel-hardening-checker -a -m json
coverage run -a --branch bin/kernel-hardening-checker -a -m show_ok
coverage run -a --branch bin/kernel-hardening-checker -a -m show_fail

echo ">>>>> check the example kconfig files, cmdline, and sysctl <<<<<"
echo "root=/dev/sda l1tf=off mds=full mitigations=off randomize_kstack_offset=on retbleed=0 iommu.passthrough=0 hey hey"  > ./cmdline_example
cat ./cmdline_example
CONFIG_DIR=`find . -name config_files`
SYSCTL_EXAMPLE=$CONFIG_DIR/distros/example_sysctls.txt
KCONFIGS=`find $CONFIG_DIR -type f | grep -e "\.config" -e "\.gz"`
COUNT=0
for C in $KCONFIGS
do
        COUNT=$(expr $COUNT + 1)
        echo "\n>>>>> checking kconfig number $COUNT <<<<<"
        coverage run -a --branch bin/kernel-hardening-checker -c $C
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example
        coverage run -a --branch bin/kernel-hardening-checker -c $C -s $SYSCTL_EXAMPLE
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m verbose > /dev/null
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m json > /dev/null
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m show_ok > /dev/null
        coverage run -a --branch bin/kernel-hardening-checker -c $C -l ./cmdline_example -s $SYSCTL_EXAMPLE -m show_fail > /dev/null
done
echo "\n>>>>> have checked $COUNT kconfigs <<<<<"

echo ">>>>> test kconfig arch detection <<<<<"
cp $CONFIG_DIR/defconfigs/x86_64_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected architecture: X86_64"
cp $CONFIG_DIR/defconfigs/i386_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected architecture: X86_32"
cp $CONFIG_DIR/defconfigs/arm_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected architecture: ARM"
cp $CONFIG_DIR/defconfigs/arm64_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected architecture: ARM64"
cp $CONFIG_DIR/defconfigs/riscv_defconfig_6.6.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config | grep "Detected architecture: RISCV"

echo ">>>>> test sysctl arch detection <<<<<"
echo "kernel.arch = x86_64" > /tmp/sysctl_arch # same as output of `sysctl kernel.arch`
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: X86_64"
echo "kernel.arch = i386" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: X86_32"
echo "kernel.arch = armv7l" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: ARM"
echo "kernel.arch = aarch64" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: ARM64"
echo "kernel.arch = armv8b" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: ARM64"
echo "kernel.arch = riscv64" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "Detected architecture: RISCV"
echo "kernel.arch = bad" > /tmp/sysctl_arch
coverage run -a --branch bin/kernel-hardening-checker -s /tmp/sysctl_arch | grep "bad is an unsupported arch, arch-dependent checks will be dropped"

echo ">>>>> check sysctl separately <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m verbose > /dev/null
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m json
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m show_ok
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -m show_fail

echo ">>>>> check sysctl.conf (it should not fail) <<<<<"
if [ ! -f "/etc/sysctl.conf" ] ; then
    echo "/etc/sysctl.conf does not exist, create a fake one"
    echo "# sysctl.conf contents here" > /etc/sysctl.conf
fi
cat /etc/sysctl.conf
coverage run -a --branch bin/kernel-hardening-checker -s /etc/sysctl.conf

echo ">>>>> check no sysctl in PATH (simulate Debian setup) <<<<<"
(
  PATH=$(echo "$PATH" | tr ":" "\n" | grep -vE "/usr/sbin|/sbin" | tr "\n" ":" | sed 's/:$//')
  coverage run -a --branch bin/kernel-hardening-checker -a
)

echo ">>>>> test -v (kernel version detection) <<<<<"
cp kernel_hardening_checker/config_files/distros/Arch_x86_64.config ./test.config
coverage run -a --branch bin/kernel-hardening-checker -c ./test.config -v /proc/version

echo "Collect coverage for error handling"

echo ">>>>> -a and any config args together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -a -c ./test.config && exit 1
coverage run -a --branch bin/kernel-hardening-checker -a -l /proc/cmdline && exit 1
coverage run -a --branch bin/kernel-hardening-checker -a -s $SYSCTL_EXAMPLE && exit 1
coverage run -a --branch bin/kernel-hardening-checker -a -v /proc/version && exit 1

echo ">>>>> -a and -p together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -a && exit 1

echo ">>>>> -a and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -a && exit 1

echo ">>>>> permission denied <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -c /proc/slabinfo && exit 1

echo ">>>>> -c and -p together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -c ./test.config && exit 1

echo ">>>>> -c and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -c ./test.config && exit 1

echo ">>>>> -l without -c <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -l /proc/cmdline && exit 1

echo ">>>>> -s and -v together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -s $SYSCTL_EXAMPLE -v /proc/version && exit 1

echo ">>>>> -s and -p together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -s $SYSCTL_EXAMPLE && exit 1

echo ">>>>> -s and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -s $SYSCTL_EXAMPLE && exit 1

echo ">>>>> -p and -v together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -v /proc/version && exit 1

echo ">>>>> -p and -g together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -g X86_64 && exit 1

echo ">>>>> wrong modes for -p <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m show_ok && exit 1
coverage run -a --branch bin/kernel-hardening-checker -p X86_64 -m show_fail && exit 1

echo ">>>>> -g and -v together <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -v /proc/version && exit 1

echo ">>>>> wrong mode for -g <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -g X86_64 -m show_ok && exit 1

echo ">>>>> no kconfig file <<<<<"
coverage run -a --branch bin/kernel-hardening-checker -c ./nosuchfile && exit 1

echo ">>>>> no kernel version <<<<<"
sed '3d' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> strange kernel version in kconfig <<<<<"
sed '3s/Linux/WAT/' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1
sed '3s/6\./a\./' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1

echo ">>>>> strange kernel version via -v <<<<<"
sed '3d' test.config > error.config
coverage run -a --branch bin/kernel-hardening-checker -c error.config -v /proc/cmdline && exit 1

echo ">>>>> no arch <<<<<"
sed '/CONFIG_X86_64=y/d' test.config > error.config
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
sed 's/CONFIG_CLANG_VERSION=0/CONFIG_CLANG_VERSION=120000/' test.config > error.config
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

echo ">>>>> broken sysctl binary <<<<<"
sudo mv /sbin/sysctl /sbin/sysctl.bak
ret_1=0; coverage run -a --branch bin/kernel-hardening-checker -a || ret_1=$? # check the test result after restoring /sbin/sysctl
sudo bash -c 'echo -e "#!/bin/bash\nexit 1" > /sbin/sysctl; chmod +x /sbin/sysctl'
ret_2=0; coverage run -a --branch bin/kernel-hardening-checker -a || ret_2=$? # check the test result after restoring /sbin/sysctl
sudo mv /sbin/sysctl.bak /sbin/sysctl
[ $ret_1 -eq 0 ] && exit 1
[ $ret_2 -eq 0 ] && exit 1

echo "The end of the functional tests"
