# kernel-hardening-checker

__(formerly kconfig-hardened-check)__<br /><br />
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/a13xp0p0v/kernel-hardening-checker?label=release)](https://github.com/a13xp0p0v/kernel-hardening-checker/tags)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)<br />
[![functional test](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/functional%20test/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/functional_test.yml)
[![functional test coverage](https://codecov.io/gh/a13xp0p0v/kernel-hardening-checker/graph/badge.svg?flag=functional_test)](https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker?flags%5B0%5D=functional_test)<br />
[![engine unit-test](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/engine%20unit-test/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/engine_unit-test.yml)
[![unit-test coverage](https://codecov.io/gh/a13xp0p0v/kernel-hardening-checker/graph/badge.svg?flag=engine_unit-test)](https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker?flags%5B0%5D=engine_unit-test)<br />
[![status-badge](https://ci.codeberg.org/api/badges/12605/status.svg)](https://ci.codeberg.org/repos/12605)
[![static analysis](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/static%20analysis/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/static_analysis.yml)
[![package test](https://github.com/a13xp0p0v/kernel-hardening-checker/workflows/package%20test/badge.svg)](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/package_test.yml)

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
  - Kernel command line arguments (boot-time)
  - Sysctl parameters (runtime)

Supported architectures:

  - X86_64
  - X86_32
  - ARM64
  - ARM
  - RISC-V

The security hardening recommendations are based on:

  - [KSPP recommended settings][1]
  - [Direct feedback from the Linux kernel maintainers][23]
  - Kernel options disabled by [grsecurity][3] to cut attack surface
  - [CLIP OS kernel configuration][2]
  - [GrapheneOS][25] recommendations
  - [SECURITY_LOCKDOWN_LSM][5] patchset
  - [CIS Benchmark][27]

I also created the [__Linux Kernel Defence Map__][4], which is a graphical representation of the
relationships between security hardening features and the corresponding vulnerability classes
or exploitation techniques.

## Attention!

Please note that changing the Linux kernel security parameters may also affect system performance
and functionality of userspace software. Therefore, when setting these parameters, consider
the threat model of your Linux-based information system and thoroughly test its typical workload.

## Installation

There are multiple options:

  - You can install the package from this Git repository using `pip`:
    ```
    python3 -m pip install git+https://github.com/a13xp0p0v/kernel-hardening-checker
    ```
    If you encounter an error due to an externally managed environment, create a virtual environment using `python3 -m venv`.

  - You can install the `kernel-hardening-checker` package via the package manager on some GNU/Linux distributions. See <https://repology.org/project/kernel-hardening-checker/versions>

  - Alternatively, you can simply run `./bin/kernel-hardening-checker` from the cloned repository without installation.

## Usage
```
$ ./bin/kernel-hardening-checker -h
usage: kernel-hardening-checker [-h] [--version]
                                [-m {verbose,json,show_ok,show_fail}] [-a]
                                [-c CONFIG] [-v KERNEL_VERSION] [-l CMDLINE]
                                [-s SYSCTL]
                                [-p {X86_64,X86_32,ARM64,ARM,RISCV}]
                                [-g {X86_64,X86_32,ARM64,ARM,RISCV}]

A tool for checking the security hardening options of the Linux kernel

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -m, --mode {verbose,json,show_ok,show_fail}
                        select a special output mode instead of the default
                        one
  -a, --autodetect      autodetect and check the security hardening options of
                        the running kernel
  -c, --config CONFIG   check the security hardening options in a Kconfig file
                        (also supports *.gz files)
  -v, --kernel-version KERNEL_VERSION
                        extract the kernel version from a version file (such
                        as /proc/version) instead of using a Kconfig file
  -l, --cmdline CMDLINE
                        check the security hardening options in a kernel
                        command line file (such as /proc/cmdline)
  -s, --sysctl SYSCTL   check the security hardening options in a sysctl
                        output file (the result of "sudo sysctl -a > file")
  -p, --print {X86_64,X86_32,ARM64,ARM,RISCV}
                        print security hardening recommendations for the
                        selected architecture
  -g, --generate {X86_64,X86_32,ARM64,ARM,RISCV}
                        generate a Kconfig fragment containing the security
                        hardening options for the selected architecture
```

## Output modes

  -  no `-m` argument for the default output mode (see the example below)
  - `-m verbose` for printing additional info:
    - the configuration options without a corresponding check
    - the internals of complex checks with AND/OR, like this:
    ```
    -------------------------------------------------------------------------------------------
        <<< OR >>>                                                                             
    CONFIG_STRICT_DEVMEM                  |kconfig|cut_attack_surface|defconfig |     y      
    CONFIG_DEVMEM                         |kconfig|cut_attack_surface|   kspp   | is not set 
    -------------------------------------------------------------------------------------------
    ```
  - `-m json` for printing the results in JSON format (for combining `kernel-hardening-checker` with other tools)
  - `-m show_ok` for showing only successful checks
  - `-m show_fail` for showing only failed checks

## Example output
```
$ ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 11, 0)
[+] Detected kconfig file of the running kernel: /boot/config-6.11.0-1018-azure
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctls to a temporary file /tmp/sysctl-traz6ijr
[+] Detected architecture: X86_64
[+] Detected compiler: GCC 130300
[!] WARNING: cmdline option "console" is found multiple times
[!] WARNING: sysctl options available for root are not found in /tmp/sysctl-traz6ijr, try checking the output of "sudo sysctl -a"
=========================================================================================================================
             option_name              | type  |      reason      | decision |desired_val | check_result
=========================================================================================================================
CONFIG_BUG                            |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_SLUB_DEBUG                     |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_THREAD_INFO_IN_TASK            |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_IOMMU_DEFAULT_PASSTHROUGH      |kconfig| self_protection  |defconfig | is not set | OK
CONFIG_IOMMU_SUPPORT                  |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_STACKPROTECTOR                 |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_STACKPROTECTOR_STRONG          |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_STRICT_KERNEL_RWX              |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_STRICT_MODULE_RWX              |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_REFCOUNT_FULL                  |kconfig| self_protection  |defconfig |     y      | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO            |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_CPU_MITIGATIONS                |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_RANDOMIZE_BASE                 |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_VMAP_STACK                     |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_LSM_MMAP_MIN_ADDR              |kconfig| self_protection  |defconfig |   65536    | FAIL: "0"
CONFIG_DEBUG_WX                       |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_WERROR                         |kconfig| self_protection  |defconfig |     y      | FAIL: "is not set"
CONFIG_X86_MCE                        |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MICROCODE                      |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MICROCODE_INTEL                |kconfig| self_protection  |defconfig |     y      | OK: CONFIG_MICROCODE is "y"
CONFIG_MICROCODE_AMD                  |kconfig| self_protection  |defconfig |     y      | OK: CONFIG_MICROCODE is "y"
CONFIG_X86_SMAP                       |kconfig| self_protection  |defconfig |     y      | OK: version >= (5, 19, 0)
CONFIG_X86_UMIP                       |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_X86_MCE_INTEL                  |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_X86_MCE_AMD                    |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MITIGATION_RETPOLINE           |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MITIGATION_RFDS                |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MITIGATION_SPECTRE_BHI         |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_RANDOMIZE_MEMORY               |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_X86_KERNEL_IBT                 |kconfig| self_protection  |defconfig |     y      | FAIL: "is not set"
CONFIG_MITIGATION_PAGE_TABLE_ISOLATION|kconfig| self_protection  |defconfig |     y      | OK
CONFIG_MITIGATION_SRSO                |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_INTEL_IOMMU                    |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_AMD_IOMMU                      |kconfig| self_protection  |defconfig |     y      | OK
CONFIG_RANDOM_KMALLOC_CACHES          |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_SLAB_MERGE_DEFAULT             |kconfig| self_protection  |   kspp   | is not set | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION         |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_SLAB_FREELIST_HARDENED         |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_SLAB_FREELIST_RANDOM           |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR         |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_FORTIFY_SOURCE                 |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_DEBUG_VIRTUAL                  |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON       |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_STATIC_USERMODEHELPER          |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM          |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_LSM                            |kconfig| self_protection  |   kspp   | *lockdown* | OK: in "landlock,lockdown,yama,integrity,apparmor"
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY    |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_ZERO_CALL_USED_REGS            |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS              |kconfig| self_protection  |   kspp   |     y      | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_KFENCE                         |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_KFENCE_SAMPLE_INTERVAL         |kconfig| self_protection  |   kspp   |    100     | FAIL: "0"
CONFIG_RANDSTRUCT_FULL                |kconfig| self_protection  |   kspp   |     y      | FAIL: is not found
CONFIG_HARDENED_USERCOPY              |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_HARDENED_USERCOPY_FALLBACK     |kconfig| self_protection  |   kspp   | is not set | OK: is not found
CONFIG_HARDENED_USERCOPY_PAGESPAN     |kconfig| self_protection  |   kspp   | is not set | OK: is not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY      |kconfig| self_protection  |   kspp   |     y      | FAIL: is not found
CONFIG_MODULE_SIG                     |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_MODULE_SIG_ALL                 |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_MODULE_SIG_SHA512              |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_MODULE_SIG_FORCE               |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON        |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA            |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION        |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_UBSAN_BOUNDS                   |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_UBSAN_LOCAL_BOUNDS             |kconfig| self_protection  |   kspp   |     y      | OK: CONFIG_UBSAN_BOUNDS is "y"
CONFIG_UBSAN_TRAP                     |kconfig| self_protection  |   kspp   |     y      | FAIL: CONFIG_UBSAN_ENUM is not "is not set"
CONFIG_UBSAN_SANITIZE_ALL             |kconfig| self_protection  |   kspp   |     y      | OK: CONFIG_UBSAN_BOUNDS is "y"
CONFIG_SCHED_CORE                     |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_DEBUG_SG                       |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_LIST_HARDENED                  |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_SCHED_STACK_END_CHECK          |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT|kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_GCC_PLUGIN_STACKLEAK           |kconfig| self_protection  |   kspp   |     y      | FAIL: is not found
CONFIG_STACKLEAK_METRICS              |kconfig| self_protection  |   kspp   | is not set | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is not "y"
CONFIG_STACKLEAK_RUNTIME_DISABLE      |kconfig| self_protection  |   kspp   | is not set | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is not "y"
CONFIG_PAGE_TABLE_CHECK               |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_PAGE_TABLE_CHECK_ENFORCED      |kconfig| self_protection  |   kspp   |     y      | FAIL: is not found
CONFIG_DEFAULT_MMAP_MIN_ADDR          |kconfig| self_protection  |   kspp   |   65536    | OK
CONFIG_HW_RANDOM_TPM                  |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_CFI_CLANG                      |kconfig| self_protection  |   kspp   |     y      | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_CFI_PERMISSIVE                 |kconfig| self_protection  |   kspp   | is not set | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_IOMMU_DEFAULT_DMA_STRICT       |kconfig| self_protection  |   kspp   |     y      | FAIL: "is not set"
CONFIG_INTEL_IOMMU_DEFAULT_ON         |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_MITIGATION_SLS                 |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_INTEL_IOMMU_SVM                |kconfig| self_protection  |   kspp   |     y      | OK
CONFIG_AMD_IOMMU_V2                   |kconfig| self_protection  |   kspp   |     y      | OK: version >= (6, 7, 0)
CONFIG_CFI_AUTO_DEFAULT               |kconfig| self_protection  |a13xp0p0v | is not set | FAIL: CONFIG_CFI_AUTO_DEFAULT is not present
CONFIG_SECURITY                       |kconfig| security_policy  |defconfig |     y      | OK
CONFIG_SECURITY_YAMA                  |kconfig| security_policy  |   kspp   |     y      | OK
CONFIG_LSM                            |kconfig| security_policy  |   kspp   |   *yama*   | OK: in "landlock,lockdown,yama,integrity,apparmor"
CONFIG_SECURITY_LANDLOCK              |kconfig| security_policy  |   kspp   |     y      | OK
CONFIG_LSM                            |kconfig| security_policy  |   kspp   | *landlock* | OK: in "landlock,lockdown,yama,integrity,apparmor"
CONFIG_SECURITY_SELINUX_DISABLE       |kconfig| security_policy  |   kspp   | is not set | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM     |kconfig| security_policy  |   kspp   | is not set | FAIL: "y"
CONFIG_SECURITY_SELINUX_DEVELOP       |kconfig| security_policy  |   kspp   | is not set | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS        |kconfig| security_policy  |   kspp   | is not set | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG         |kconfig| security_policy  |   kspp   | is not set | OK
CONFIG_SECURITY_SELINUX               |kconfig| security_policy  |a13xp0p0v |     y      | OK
CONFIG_LSM                            |kconfig| security_policy  |a13xp0p0v | *selinux*  | OK: "apparmor" is in CONFIG_LSM
CONFIG_SECCOMP                        |kconfig|cut_attack_surface|defconfig |     y      | OK
CONFIG_SECCOMP_FILTER                 |kconfig|cut_attack_surface|defconfig |     y      | OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF         |kconfig|cut_attack_surface|defconfig |     y      | OK
CONFIG_STRICT_DEVMEM                  |kconfig|cut_attack_surface|defconfig |     y      | OK
CONFIG_X86_INTEL_TSX_MODE_OFF         |kconfig|cut_attack_surface|defconfig |     y      | OK
CONFIG_SECURITY_DMESG_RESTRICT        |kconfig|cut_attack_surface|   kspp   |     y      | OK
CONFIG_ACPI_CUSTOM_METHOD             |kconfig|cut_attack_surface|   kspp   | is not set | OK: is not found
CONFIG_COMPAT_BRK                     |kconfig|cut_attack_surface|   kspp   | is not set | OK
CONFIG_DEVKMEM                        |kconfig|cut_attack_surface|   kspp   | is not set | OK: is not found
CONFIG_BINFMT_MISC                    |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "m"
CONFIG_INET_DIAG                      |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "m"
CONFIG_KEXEC                          |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_PROC_KCORE                     |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_LEGACY_PTYS                    |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_HIBERNATION                    |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_COMPAT                         |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_IA32_EMULATION                 |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_X86_X32                        |kconfig|cut_attack_surface|   kspp   | is not set | OK: is not found
CONFIG_X86_X32_ABI                    |kconfig|cut_attack_surface|   kspp   | is not set | OK
CONFIG_MODIFY_LDT_SYSCALL             |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_OABI_COMPAT                    |kconfig|cut_attack_surface|   kspp   | is not set | OK: is not found
CONFIG_X86_MSR                        |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "m"
CONFIG_LEGACY_TIOCSTI                 |kconfig|cut_attack_surface|   kspp   | is not set | OK
CONFIG_MODULE_FORCE_LOAD              |kconfig|cut_attack_surface|   kspp   | is not set | OK
CONFIG_MODULES                        |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_DEVMEM                         |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_IO_STRICT_DEVMEM               |kconfig|cut_attack_surface|   kspp   |     y      | FAIL: "is not set"
CONFIG_LDISC_AUTOLOAD                 |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION         |kconfig|cut_attack_surface|   kspp   | is not set | FAIL: "y"
CONFIG_COMPAT_VDSO                    |kconfig|cut_attack_surface|   kspp   | is not set | OK
CONFIG_DRM_LEGACY                     |kconfig|cut_attack_surface|maintainer| is not set | OK: is not found
CONFIG_FB                             |kconfig|cut_attack_surface|maintainer| is not set | FAIL: "y"
CONFIG_VT                             |kconfig|cut_attack_surface|maintainer| is not set | FAIL: "y"
CONFIG_BLK_DEV_FD                     |kconfig|cut_attack_surface|maintainer| is not set | OK
CONFIG_BLK_DEV_FD_RAWCMD              |kconfig|cut_attack_surface|maintainer| is not set | OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT     |kconfig|cut_attack_surface|maintainer| is not set | OK: is not found
CONFIG_N_GSM                          |kconfig|cut_attack_surface|maintainer| is not set | FAIL: "m"
CONFIG_ZSMALLOC_STAT                  |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_DEBUG_KMEMLEAK                 |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_BINFMT_AOUT                    |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_KPROBE_EVENTS                  |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_UPROBE_EVENTS                  |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_GENERIC_TRACER                 |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_FUNCTION_TRACER                |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_STACK_TRACER                   |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_HIST_TRIGGERS                  |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_BLK_DEV_IO_TRACE               |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_PROC_VMCORE                    |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_PROC_PAGE_MONITOR              |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_USELIB                         |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_CHECKPOINT_RESTORE             |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_USERFAULTFD                    |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_HWPOISON_INJECT                |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_MEM_SOFT_DIRTY                 |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_DEVPORT                        |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_DEBUG_FS                       |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION       |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_FAIL_FUTEX                     |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_PUNIT_ATOM_DEBUG               |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_ACPI_CONFIGFS                  |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_EDAC_DEBUG                     |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_DRM_I915_DEBUG                 |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_DVB_C8SECTPFE                  |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_MTD_SLRAM                      |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_MTD_PHRAM                      |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_IO_URING                       |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_KCMP                           |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_RSEQ                           |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_LATENCYTOP                     |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_KCOV                           |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT      |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_SUNRPC_DEBUG                   |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_X86_16BIT                      |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_BLK_DEV_UBLK                   |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_SMB_SERVER                     |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_XFS_ONLINE_SCRUB_STATS         |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_CACHESTAT_SYSCALL              |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS         |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS         |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_PROVE_LOCKING                  |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_TEST_DEBUG_VIRTUAL             |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_MPTCP                          |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_TLS                            |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_TIPC                           |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_IP_SCTP                        |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "m"
CONFIG_KGDB                           |kconfig|cut_attack_surface|  grsec   | is not set | FAIL: "y"
CONFIG_PTDUMP_DEBUGFS                 |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_X86_PTDUMP                     |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_DEBUG_CLOSURES                 |kconfig|cut_attack_surface|  grsec   | is not set | OK
CONFIG_BCACHE_CLOSURES_DEBUG          |kconfig|cut_attack_surface|  grsec   | is not set | OK: is not found
CONFIG_STAGING                        |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_KSM                            |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_KALLSYMS                       |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_KEXEC_FILE                     |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_CRASH_DUMP                     |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_USER_NS                        |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_X86_CPUID                      |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "m"
CONFIG_X86_IOPL_IOPERM                |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_ACPI_TABLE_UPGRADE             |kconfig|cut_attack_surface|  clipos  | is not set | OK
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS       |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_AIO                            |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_MAGIC_SYSRQ                    |kconfig|cut_attack_surface|  clipos  | is not set | FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL             |kconfig|cut_attack_surface|grapheneos| is not set | FAIL: "y"
CONFIG_EFI_TEST                       |kconfig|cut_attack_surface| lockdown | is not set | FAIL: "m"
CONFIG_MMIOTRACE_TEST                 |kconfig|cut_attack_surface| lockdown | is not set | OK
CONFIG_KPROBES                        |kconfig|cut_attack_surface| lockdown | is not set | FAIL: "y"
CONFIG_BPF_SYSCALL                    |kconfig|cut_attack_surface| lockdown | is not set | FAIL: "y"
CONFIG_MMIOTRACE                      |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "y"
CONFIG_LIVEPATCH                      |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "y"
CONFIG_IP_DCCP                        |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "m"
CONFIG_FTRACE                         |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "y"
CONFIG_VIDEO_VIVID                    |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "m"
CONFIG_INPUT_EVBUG                    |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "m"
CONFIG_CORESIGHT                      |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK: is not found
CONFIG_XFS_SUPPORT_V4                 |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED          |kconfig|cut_attack_surface|a13xp0p0v | is not set | FAIL: "y"
CONFIG_FAULT_INJECTION                |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK
CONFIG_ARM_PTDUMP_DEBUGFS             |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK: is not found
CONFIG_ARM_PTDUMP                     |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG            |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK
CONFIG_LKDTM                          |kconfig|cut_attack_surface|a13xp0p0v | is not set | OK
CONFIG_TRIM_UNUSED_KSYMS              |kconfig|cut_attack_surface|a13xp0p0v |     y      | FAIL: "is not set"
CONFIG_SYN_COOKIES                    |kconfig| network_security |defconfig |     y      | OK
CONFIG_COREDUMP                       |kconfig| harden_userspace |  clipos  | is not set | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS             |kconfig| harden_userspace |a13xp0p0v |     32     | OK
CONFIG_ARCH_MMAP_RND_COMPAT_BITS      |kconfig| harden_userspace |a13xp0p0v |     16     | OK
CONFIG_X86_USER_SHADOW_STACK          |kconfig| harden_userspace |   kspp   |     y      | OK
nosmep                                |cmdline| self_protection  |defconfig | is not set | OK: is not found
nosmap                                |cmdline| self_protection  |defconfig | is not set | OK: is not found
nokaslr                               |cmdline| self_protection  |defconfig | is not set | OK: is not found
nopti                                 |cmdline| self_protection  |defconfig | is not set | OK: is not found
no_hash_pointers                      |cmdline| self_protection  |defconfig | is not set | OK: is not found
nospectre_v1                          |cmdline| self_protection  |defconfig | is not set | OK: is not found
nospectre_v2                          |cmdline| self_protection  |defconfig | is not set | OK: is not found
nospectre_bhb                         |cmdline| self_protection  |defconfig | is not set | OK: is not found
nospec_store_bypass_disable           |cmdline| self_protection  |defconfig | is not set | OK: is not found
dis_ucode_ldr                         |cmdline| self_protection  |defconfig | is not set | OK: is not found
arm64.nobti                           |cmdline| self_protection  |defconfig | is not set | OK: is not found
arm64.nopauth                         |cmdline| self_protection  |defconfig | is not set | OK: is not found
arm64.nomte                           |cmdline| self_protection  |defconfig | is not set | OK: is not found
iommu.passthrough                     |cmdline| self_protection  |defconfig |     0      | OK: CONFIG_IOMMU_DEFAULT_PASSTHROUGH is "is not set"
rodata                                |cmdline| self_protection  |defconfig |     on     | OK: rodata is not found
spectre_v2                            |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
spectre_v2_user                       |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
spectre_bhi                           |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
spec_store_bypass_disable             |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
l1tf                                  |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
mds                                   |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
tsx_async_abort                       |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
srbds                                 |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
mmio_stale_data                       |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
retbleed                              |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
spec_rstack_overflow                  |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
gather_data_sampling                  |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
reg_file_data_sampling                |cmdline| self_protection  |defconfig | is not off | FAIL: is off, not found
slab_merge                            |cmdline| self_protection  |   kspp   | is not set | OK: is not found
slub_merge                            |cmdline| self_protection  |   kspp   | is not set | OK: is not found
page_alloc.shuffle                    |cmdline| self_protection  |   kspp   |     1      | FAIL: is not found
slab_nomerge                          |cmdline| self_protection  |   kspp   | is present | FAIL: is not present
init_on_alloc                         |cmdline| self_protection  |   kspp   |     1      | OK: CONFIG_INIT_ON_ALLOC_DEFAULT_ON is "y"
init_on_free                          |cmdline| self_protection  |   kspp   |     1      | FAIL: is not found
hardened_usercopy                     |cmdline| self_protection  |   kspp   |     1      | OK: CONFIG_HARDENED_USERCOPY is "y"
slab_common.usercopy_fallback         |cmdline| self_protection  |   kspp   | is not set | OK: is not found
kfence.sample_interval                |cmdline| self_protection  |   kspp   |    100     | FAIL: is not found
lockdown                              |cmdline| self_protection  |   kspp   |confidentiality| FAIL: is not found
module.sig_enforce                    |cmdline| self_protection  |   kspp   |     1      | FAIL: is not found
efi                                   |cmdline| self_protection  |   kspp   |*disable_early_pci_dma*| FAIL: is not found
randomize_kstack_offset               |cmdline| self_protection  |   kspp   |     1      | OK: CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is "y"
mitigations                           |cmdline| self_protection  |   kspp   | auto,nosmt | FAIL: is not found
intel_iommu                           |cmdline| self_protection  |   kspp   |     on     | OK: CONFIG_INTEL_IOMMU_DEFAULT_ON is "y"
iommu.strict                          |cmdline| self_protection  |   kspp   |     1      | FAIL: is not found
pti                                   |cmdline| self_protection  |   kspp   |     on     | FAIL: is not found
cfi                                   |cmdline| self_protection  |   kspp   |    kcfi    | FAIL: is not found
iommu                                 |cmdline| self_protection  |  clipos  |   force    | FAIL: is not found
tsx                                   |cmdline|cut_attack_surface|defconfig |    off     | OK: CONFIG_X86_INTEL_TSX_MODE_OFF is "y"
nosmt                                 |cmdline|cut_attack_surface|   kspp   | is present | FAIL: is not present
vsyscall                              |cmdline|cut_attack_surface|   kspp   |    none    | FAIL: is not found
vdso32                                |cmdline|cut_attack_surface|   kspp   |     0      | OK: CONFIG_COMPAT_VDSO is "is not set"
ia32_emulation                        |cmdline|cut_attack_surface|   kspp   |     0      | FAIL: is not found
debugfs                               |cmdline|cut_attack_surface|  grsec   |    off     | FAIL: is not found
sysrq_always_enabled                  |cmdline|cut_attack_surface|grapheneos| is not set | OK: is not found
bdev_allow_write_mounted              |cmdline|cut_attack_surface|a13xp0p0v |     0      | FAIL: is not found
norandmaps                            |cmdline| harden_userspace |defconfig | is not set | OK: is not found
net.core.bpf_jit_harden               |sysctl | self_protection  |   kspp   |     2      | FAIL: is not found
vm.mmap_min_addr                      |sysctl | self_protection  |   kspp   |   65536    | OK
kernel.oops_limit                     |sysctl | self_protection  |a13xp0p0v |    100     | FAIL: "10000"
kernel.warn_limit                     |sysctl | self_protection  |a13xp0p0v |    100     | FAIL: "0"
kernel.dmesg_restrict                 |sysctl |cut_attack_surface|   kspp   |     1      | OK
kernel.perf_event_paranoid            |sysctl |cut_attack_surface|   kspp   |     3      | FAIL: "4"
dev.tty.ldisc_autoload                |sysctl |cut_attack_surface|   kspp   |     0      | FAIL: "1"
kernel.kptr_restrict                  |sysctl |cut_attack_surface|   kspp   |     2      | FAIL: "1"
dev.tty.legacy_tiocsti                |sysctl |cut_attack_surface|   kspp   |     0      | OK
user.max_user_namespaces              |sysctl |cut_attack_surface|   kspp   |     0      | FAIL: "63952"
kernel.kexec_load_disabled            |sysctl |cut_attack_surface|   kspp   |     1      | FAIL: "0"
kernel.unprivileged_bpf_disabled      |sysctl |cut_attack_surface|   kspp   |     1      | FAIL: "2"
vm.unprivileged_userfaultfd           |sysctl |cut_attack_surface|   kspp   |     0      | OK
kernel.modules_disabled               |sysctl |cut_attack_surface|   kspp   |     1      | FAIL: "0"
kernel.io_uring_disabled              |sysctl |cut_attack_surface|  grsec   |     2      | FAIL: "0"
kernel.sysrq                          |sysctl |cut_attack_surface|a13xp0p0v |     0      | FAIL: "176"
net.ipv4.icmp_ignore_bogus_error_responses|sysctl | network_security |   cis    |     1      | OK
net.ipv4.icmp_echo_ignore_broadcasts  |sysctl | network_security |   cis    |     1      | OK
net.ipv4.conf.all.accept_redirects    |sysctl | network_security |   cis    |     0      | OK
net.ipv4.conf.default.accept_redirects|sysctl | network_security |   cis    |     0      | FAIL: "1"
net.ipv6.conf.all.accept_redirects    |sysctl | network_security |   cis    |     0      | FAIL: "1"
net.ipv6.conf.default.accept_redirects|sysctl | network_security |   cis    |     0      | FAIL: "1"
net.ipv4.conf.all.accept_source_route |sysctl | network_security |   cis    |     0      | OK
net.ipv4.conf.default.accept_source_route|sysctl | network_security |   cis    |     0      | FAIL: "1"
net.ipv6.conf.all.accept_source_route |sysctl | network_security |   cis    |     0      | OK
net.ipv6.conf.default.accept_source_route|sysctl | network_security |   cis    |     0      | OK
net.ipv4.tcp_syncookies               |sysctl | network_security |   cis    |     1      | OK
net.ipv6.conf.all.accept_ra           |sysctl | network_security |   cis    |     0      | FAIL: "1"
net.ipv6.conf.default.accept_ra       |sysctl | network_security |   cis    |     0      | FAIL: "1"
fs.protected_symlinks                 |sysctl | harden_userspace |   kspp   |     1      | OK
fs.protected_hardlinks                |sysctl | harden_userspace |   kspp   |     1      | OK
fs.protected_fifos                    |sysctl | harden_userspace |   kspp   |     2      | FAIL: "1"
fs.protected_regular                  |sysctl | harden_userspace |   kspp   |     2      | OK
fs.suid_dumpable                      |sysctl | harden_userspace |   kspp   |     0      | FAIL: "2"
kernel.randomize_va_space             |sysctl | harden_userspace |   kspp   |     2      | OK
kernel.yama.ptrace_scope              |sysctl | harden_userspace |   kspp   |     3      | FAIL: "1"
vm.mmap_rnd_bits                      |sysctl | harden_userspace |a13xp0p0v |     32     | FAIL: is not found
vm.mmap_rnd_compat_bits               |sysctl | harden_userspace |a13xp0p0v |     16     | FAIL: is not found

[+] Config check is finished: 'OK' - 164 / 'FAIL' - 158
```

## Generating a Kconfig fragment with the security hardening options

With the `-g` argument, the tool generates a Kconfig fragment with the security hardening options for the selected architecture.

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
[27]: https://learn.cisecurity.org/benchmarks
