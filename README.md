# kernel-hardening-checker

__(formerly kconfig-hardened-check)__<br /><br />
[![functional test](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/functional%20test/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/functional_test.yml)
[![functional test coverage](https://codecov.io/gh/a13xp0p0v/kernel-hardening-checker/graph/badge.svg?flag=functional_test)](https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker?flags%5B0%5D=functional_test)<br />
[![engine unit-test](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/engine%20unit-test/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/engine_unit-test.yml)
[![unit-test coverage](https://codecov.io/gh/a13xp0p0v/kernel-hardening-checker/graph/badge.svg?flag=engine_unit-test)](https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker?flags%5B0%5D=engine_unit-test)<br />
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/a13xp0p0v/kernel-hardening-checker?label=release)](https://github.com/a13xp0p0v/kernel-hardening-checker/tags)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Motivation

There are plenty of security hardening options for the Linux kernel. A lot of them are
not enabled by the major distros. We have to enable these options ourselves to
make our systems more secure.

But nobody likes checking configs manually. So let the computers do their job!

__kernel-hardening-checker__ (formerly __kconfig-hardened-check__) is a tool for checking the security hardening options of the Linux kernel.

License: GPL-3.0.

## Repositories

 - At GitHub <https://github.com/a13xp0p0v/kernel-hardening-checker>
 - At Codeberg: <https://codeberg.org/a13xp0p0v/kernel-hardening-checker> (go there if something goes wrong with GitHub)
 - At GitFlic: <https://gitflic.ru/project/a13xp0p0v/kernel-hardening-checker>

## Features

`kernel-hardening-checker` supports checking:

  - Kconfig options (compile-time)
  - Kernel cmdline arguments (boot-time)
  - Sysctl parameters (runtime)

Supported microarchitectures:

  - X86_64
  - X86_32
  - ARM64
  - ARM

The security hardening recommendations are based on:

  - [KSPP recommended settings][1]
  - [Direct feedback from the Linux kernel maintainers][23]
  - Kernel options disabled by [grsecurity][3] to cut attack surface
  - [CLIP OS kernel configuration][2]
  - [GrapheneOS][25] recommendations
  - [SECURITY_LOCKDOWN_LSM][5] patchset

I also created the [__Linux Kernel Defence Map__][4], which is a graphical representation of the
relationships between security hardening features and the corresponding vulnerability classes
or exploitation techniques.

## Attention!

Changing Linux kernel security parameters may also affect system performance
and functionality of userspace software. So for choosing these parameters, consider
the threat model of your Linux-based information system and perform thorough testing
of its typical workload.

## Installation

You can install the package:

```
pip install git+https://github.com/a13xp0p0v/kernel-hardening-checker
```

or simply run `./bin/kernel-hardening-checker` from the cloned repository.

Some Linux distributions also provide `kernel-hardening-checker` as a package.

## Usage
```
./bin/kernel-hardening-checker -h
usage: kernel-hardening-checker [-h] [--version] [-m {verbose,json,show_ok,show_fail}]
                                [-a] [-c CONFIG] [-v KERNEL_VERSION] [-l CMDLINE] [-s SYSCTL]
                                [-p {X86_64,X86_32,ARM64,ARM}]
                                [-g {X86_64,X86_32,ARM64,ARM}]

A tool for checking the security hardening options of the Linux kernel

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
  -a, --autodetect      autodetect and check the security hardening options
                        of the running kernel
  -c CONFIG, --config CONFIG
                        check the security hardening options in the Kconfig file
                        (also supports *.gz files)
  -v KERNEL_VERSION, --kernel-version KERNEL_VERSION
                        extract version from the kernel version file (contents of
                        /proc/version) instead of Kconfig file
  -l CMDLINE, --cmdline CMDLINE
                        check the security hardening options in the kernel cmdline file
                        (contents of /proc/cmdline)
  -s SYSCTL, --sysctl SYSCTL
                        check the security hardening options in the sysctl output file
                        (`sudo sysctl -a > file`)
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print the security hardening recommendations for the selected
                        microarchitecture
  -g {X86_64,X86_32,ARM64,ARM}, --generate {X86_64,X86_32,ARM64,ARM}
                        generate a Kconfig fragment with the security hardening options
                        for the selected microarchitecture
```

## Output modes

  -  no `-m` argument for the default output mode (see the example below)
  - `-m verbose` for printing additional info:
    - config options without a corresponding check
    - internals of complex checks with AND/OR, like this:
```
-------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |defconfig |cut_attack_surface
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface
-------------------------------------------------------------------------------------------
```
  - `-m show_fail` for showing only the failed checks
  - `-m show_ok` for showing only the successful checks
  - `-m json` for printing the results in JSON format (for combining `kernel-hardening-checker` with other tools)

## Example output
```
$ ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 5, 0)
[+] Detected kconfig file of the running kernel: /boot/config-6.5.0-1025-azure
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctl output to /tmp/sysctl-n7hd4ab2
[+] Detected microarchitecture: X86_64
[+] Detected compiler: GCC 110400
[!] WARNING: cmdline option "console" is found multiple times
[!] WARNING: sysctl options available for root are not found in /tmp/sysctl-n7hd4ab2, try checking the output of `sudo sysctl -a`
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | OK: CONFIG_SPECULATION_MITIGATIONS is "y"
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_DEBUG_WX                         |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_WERROR                           |kconfig|     y      |defconfig | self_protection  | FAIL: "is not set"
CONFIG_X86_MCE                          |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SYN_COOKIES                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_MICROCODE                        |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_MICROCODE_INTEL                  |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_MICROCODE_AMD                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_SMAP                         |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 19, 0)
CONFIG_X86_UMIP                         |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_MCE_INTEL                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_MCE_AMD                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_MITIGATION_RETPOLINE             |kconfig|     y      |defconfig | self_protection  | OK: CONFIG_RETPOLINE is "y"
CONFIG_MITIGATION_RFDS                  |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_MITIGATION_SPECTRE_BHI           |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_RANDOMIZE_MEMORY                 |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_KERNEL_IBT                   |kconfig|     y      |defconfig | self_protection  | FAIL: "is not set"
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION  |kconfig|     y      |defconfig | self_protection  | OK: CONFIG_PAGE_TABLE_ISOLATION is "y"
CONFIG_MITIGATION_SRSO                  |kconfig|     y      |defconfig | self_protection  | OK: CONFIG_CPU_SRSO is "y"
CONFIG_INTEL_IOMMU                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_AMD_IOMMU                        |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_CORE                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_LIST_HARDENED                    |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE_SAMPLE_INTERVAL           |kconfig|    100     |   kspp   | self_protection  | FAIL: "0"
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | OK: CONFIG_UBSAN_BOUNDS is "y"
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_ENUM is not "is not set"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_GCC_PLUGIN_STACKLEAK             |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_STACKLEAK_METRICS                |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is not "y"
CONFIG_STACKLEAK_RUNTIME_DISABLE        |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is not "y"
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT  |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_PAGE_TABLE_CHECK                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_PAGE_TABLE_CHECK_ENFORCED        |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_HW_RANDOM_TPM                    |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   65536    |   kspp   | self_protection  | OK
CONFIG_IOMMU_DEFAULT_DMA_STRICT         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_IOMMU_DEFAULT_PASSTHROUGH        |kconfig| is not set |   kspp   | self_protection  | OK
CONFIG_INTEL_IOMMU_DEFAULT_ON           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MITIGATION_SLS                   |kconfig|     y      |   kspp   | self_protection  | OK: CONFIG_SLS is "y"
CONFIG_INTEL_IOMMU_SVM                  |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_AMD_IOMMU_V2                     |kconfig|     y      |   kspp   | self_protection  | FAIL: "m"
CONFIG_CFI_AUTO_DEFAULT                 |kconfig| is not set |a13xp0p0v | self_protection  | FAIL: CONFIG_CFI_AUTO_DEFAULT is not present
CONFIG_SECURITY                         |kconfig|     y      |defconfig | security_policy  | OK
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_X86_INTEL_TSX_MODE_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_COMPAT_VDSO                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "m"
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "m"
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: "is not set"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     32     |a13xp0p0v | harden_userspace | OK
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     16     |a13xp0p0v | harden_userspace | OK
CONFIG_X86_USER_SHADOW_STACK            |kconfig|     y      |   kspp   | harden_userspace | FAIL: is not found
nosmep                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nosmap                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nokaslr                                 |cmdline| is not set |defconfig | self_protection  | OK: is not found
nopti                                   |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v1                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v2                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_bhb                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospec_store_bypass_disable             |cmdline| is not set |defconfig | self_protection  | OK: is not found
dis_ucode_ldr                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nobti                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nopauth                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nomte                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
spectre_v2                              |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
spectre_v2_user                         |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
spectre_bhi                             |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
spec_store_bypass_disable               |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
l1tf                                    |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
mds                                     |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
tsx_async_abort                         |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
srbds                                   |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
mmio_stale_data                         |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
retbleed                                |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
spec_rstack_overflow                    |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
gather_data_sampling                    |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
reg_file_data_sampling                  |cmdline| is not off |defconfig | self_protection  | FAIL: is off, not found
rodata                                  |cmdline|     on     |defconfig | self_protection  | OK: rodata is not found
slab_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
slub_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
page_alloc.shuffle                      |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
slab_nomerge                            |cmdline| is present |   kspp   | self_protection  | FAIL: is not present
init_on_alloc                           |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_INIT_ON_ALLOC_DEFAULT_ON is "y"
init_on_free                            |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
hardened_usercopy                       |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY is "y"
slab_common.usercopy_fallback           |cmdline| is not set |   kspp   | self_protection  | OK: is not found
kfence.sample_interval                  |cmdline|    100     |   kspp   | self_protection  | FAIL: is not found
iommu.strict                            |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
iommu.passthrough                       |cmdline|     0      |   kspp   | self_protection  | OK: CONFIG_IOMMU_DEFAULT_PASSTHROUGH is "is not set"
randomize_kstack_offset                 |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is "y"
mitigations                             |cmdline| auto,nosmt |   kspp   | self_protection  | FAIL: is not found
pti                                     |cmdline|     on     |   kspp   | self_protection  | FAIL: is not found
cfi                                     |cmdline|    kcfi    |   kspp   | self_protection  | FAIL: is not found
iommu                                   |cmdline|   force    |  clipos  | self_protection  | FAIL: is not found
tsx                                     |cmdline|    off     |defconfig |cut_attack_surface| OK: CONFIG_X86_INTEL_TSX_MODE_OFF is "y"
nosmt                                   |cmdline| is present |   kspp   |cut_attack_surface| FAIL: is not present
vsyscall                                |cmdline|    none    |   kspp   |cut_attack_surface| FAIL: is not found
vdso32                                  |cmdline|     0      |   kspp   |cut_attack_surface| OK: CONFIG_COMPAT_VDSO is "is not set"
debugfs                                 |cmdline|    off     |  grsec   |cut_attack_surface| FAIL: is not found
sysrq_always_enabled                    |cmdline| is not set |grapheneos|cut_attack_surface| OK: is not found
bdev_allow_write_mounted                |cmdline|     0      |a13xp0p0v |cut_attack_surface| OK: CONFIG_BLK_DEV_WRITE_MOUNTED is not found
ia32_emulation                          |cmdline|     0      |a13xp0p0v |cut_attack_surface| FAIL: is not found
norandmaps                              |cmdline| is not set |defconfig | harden_userspace | OK: is not found
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: is not found
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
vm.mmap_min_addr                        |sysctl |   65536    |   kspp   | self_protection  | OK
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| OK
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| FAIL: "4"
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "63899"
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: "1"
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "2"
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: "176"
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: "1"
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | OK
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | FAIL: "2"
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | OK
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: "1"
vm.mmap_rnd_bits                        |sysctl |     32     |a13xp0p0v | harden_userspace | FAIL: is not found
vm.mmap_rnd_compat_bits                 |sysctl |     16     |a13xp0p0v | harden_userspace | FAIL: is not found

[+] Config check is finished: 'OK' - 145 / 'FAIL' - 153
```

## Generating a Kconfig fragment with the security hardening options

With the `-g` argument, the tool generates a Kconfig fragment with the security hardening options for the selected microarchitecture.

This Kconfig fragment can be merged with the existing Linux kernel config:
```
$ ./bin/kernel-hardening-checker -g X86_64 > /tmp/fragment
$ cd ~/linux-src/
$ ./scripts/kconfig/merge_config.sh .config /tmp/fragment
Using .config as base
Merging /tmp/fragment
Value of CONFIG_BUG_ON_DATA_CORRUPTION is redefined by fragment /tmp/fragment:
Previous value: # CONFIG_BUG_ON_DATA_CORRUPTION is not set
New value: CONFIG_BUG_ON_DATA_CORRUPTION=y
 ...
```

## Thanks

Thanks to the [contributors][26] and users of this project!

## Questions and answers

__Q:__ How all these kernel parameters influence the Linux kernel security?

__A:__ To answer this question, you can use the `kernel-hardening-checker` [sources of recommendations][24]
and the [Linux Kernel Defence Map][4] with its references.

<br />

__Q:__ How disabling `CONFIG_USER_NS` cuts the attack surface? It's needed for containers!

__A:__ Yes, the `CONFIG_USER_NS` option provides some isolation between the userspace programs,
but the tool recommends disabling it to cut the attack surface __of the kernel__.

The rationale:

  - An LWN article about the corresponding LKML discussion: https://lwn.net/Articles/673597/

  - A twitter thread about `CONFIG_USER_NS` and security: https://twitter.com/robertswiecki/status/1095447678949953541

  - A good overview of the trade-off between having user namespaces enabled, disabled and available only for root: https://github.com/NixOS/nixpkgs/pull/84522#issuecomment-614640601

<br />

__Q:__ KSPP and CLIP OS recommend `CONFIG_PANIC_ON_OOPS=y`. Why doesn't this tool do the same?

__A:__ I can't support this recommendation because:
  - It decreases system robustness (kernel oops is still not a rare situation even on production systems)
  - It allows easier denial-of-service attacks for the whole system

You should enable `CONFIG_PANIC_ON_OOPS` if:
  - Your kernel doesn't encounter oopses during a typical workload
  - Occasional system reboot is not a problem in your use case

I see a good compromise, which `kernel-hardening-checker` recommends:
  - Enable the `CONFIG_BUG` kconfig option. If a kernel oops happens in the process context, the offending/attacking process is killed. In other cases, the kernel panics, which is similar to `CONFIG_PANIC_ON_OOPS=y`.
  - Set the sysctl options `kernel.oops_limit` and `kernel.warn_limit` to `100`, for example. On the one hand, this value doesn't allow easy DoS. On the other hand, it is not too large to miss the vulnerability exploitation attempts generating a lot of kernel warnings or oopses.

<br />

__Q:__ Why enabling `CONFIG_STATIC_USERMODEHELPER` breaks various things in my GNU/Linux system?
Do I really need that feature?

__A:__ Linux kernel usermode helpers can be used for privilege escalation in kernel exploits
([example 1][9], [example 2][10]). `CONFIG_STATIC_USERMODEHELPER` prevents that method. But it
requires the corresponding support in the userspace: see the [example implementation][11] by
Tycho Andersen [@tych0][12].

<br />

__Q:__ What about performance impact of these security hardening options?

__A:__ Ike Devolder [@BlackIkeEagle][7] made some performance tests and described the results in [this article][8].
A more detailed evaluation is in the TODO list (the issue [#66][21]).

<br />

__Q:__ Can I easily check which kernel versions support some Kconfig option?

__A:__ Yes. See the [LKDDb][18] project (Linux Kernel Driver Database) by Giacomo Catenazzi [@cateee][19].
You can use it for the `mainline` or `stable` tree from [kernel.org][20] or for your custom kernel sources.

<br />

__Q:__ Does my kernel have all those mitigations of Transient Execution Vulnerabilities in my hardware?

__A:__ Checking the kernel config is not enough to answer this question.
I highly recommend using [spectre-meltdown-checker][13] tool maintained by Stéphane Lesimple [@speed47][14].

<br />

__Q:__ Why the `CONFIG_GCC_PLUGINS` option is automatically disabled during the kernel compilation?

__A:__ It means that your gcc doesn't support plugins. For example, if you have `gcc-14` on Ubuntu,
try to install `gcc-14-plugin-dev` package, it should help.


[1]: https://kspp.github.io/Recommended_Settings
[2]: https://docs.clip-os.org/clipos/kernel.html#configuration
[3]: https://grsecurity.net/
[4]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[5]: https://lwn.net/Articles/791863/
[6]: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38
[7]: https://github.com/BlackIkeEagle
[8]: https://blog.herecura.eu/blog/2020-05-30-kconfig-hardening-tests/
[9]: https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
[10]: https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
[11]: https://github.com/tych0/huldufolk
[12]: https://github.com/tych0
[13]: https://github.com/speed47/spectre-meltdown-checker
[14]: https://github.com/speed47
[15]: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53
[16]: https://github.com/a13xp0p0v/kernel-hardening-checker/pull/54
[17]: https://github.com/a13xp0p0v/kernel-hardening-checker/pull/62
[18]: https://cateee.net/lkddb/web-lkddb/
[19]: https://github.com/cateee/lkddb
[20]: https://kernel.org/
[21]: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/66
[22]: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/56
[23]: https://github.com/a13xp0p0v/kernel-hardening-checker/issues?q=label%3Akernel_maintainer_feedback
[24]: https://github.com/a13xp0p0v/kernel-hardening-checker#motivation
[25]: https://grapheneos.org/features
[26]: https://github.com/a13xp0p0v/kernel-hardening-checker/graphs/contributors
