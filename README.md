# kconfig-hardened-check

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/a13xp0p0v/kconfig-hardened-check?label=release)
![functional test](https://github.com/a13xp0p0v/kconfig-hardened-check/workflows/functional%20test/badge.svg)
[![Coverage Status](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/graph/badge.svg)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check)

## Motivation

There are plenty of security hardening options for the Linux kernel. A lot of them are
not enabled by the major distros. We have to enable these options ourselves to
make our systems more secure.

But nobody likes checking configs manually. So let the computers do their job!

__kconfig-hardened-check__ helps me to check the Linux kernel options
against my security hardening preferences, which are based on the

  - [KSPP recommended settings][1]
  - [CLIP OS kernel configuration][2]
  - Last public [grsecurity][3] patch (options which they disable)
  - [SECURITY_LOCKDOWN_LSM][5] patchset
  - [Direct feedback from the Linux kernel maintainers][23]

This tool supports checking __Kconfig__ options and __kernel cmdline__ parameters.

I also created the [__Linux Kernel Defence Map__][4], which is a graphical representation of the
relationships between security hardening features and the corresponding vulnerability classes
or exploitation techniques.

__Attention!__ Changing Linux kernel security parameters may also affect system performance
and functionality of userspace software. So for choosing these parameters consider
the threat model of your Linux-based information system and perform thorough testing
of its typical workload.

## Supported microarchitectures

  - X86_64
  - X86_32
  - ARM64
  - ARM

TODO: RISC-V (issue [#56][22])

## Installation

You can install the package:

```
pip install git+https://github.com/a13xp0p0v/kconfig-hardened-check
```

or simply run `./bin/kconfig-hardened-check` from the cloned repository.

Some Linux distributions also provide `kconfig-hardened-check` as a package.

## Usage
```
usage: kconfig-hardened-check [-h] [--version] [-p {X86_64,X86_32,ARM64,ARM}]
                              [-c CONFIG]
                              [-l CMDLINE]
                              [-m {verbose,json,show_ok,show_fail}]

A tool for checking the security hardening options of the Linux kernel

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print security hardening preferences for the selected architecture
  -c CONFIG, --config CONFIG
                        check the kernel kconfig file against these preferences
  -l CMDLINE, --cmdline CMDLINE
                        check the kernel cmdline file against these preferences
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
```

## Output modes

  -  no `-m` argument for the default output mode (see the example below)
  - `-m verbose` for printing additional info:
    - config options without a corresponding check
    - internals of complex checks with AND/OR, like this:
```
-------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             
CONFIG_STRICT_DEVMEM                         |      y      |defconfig | cut_attack_surface 
CONFIG_DEVMEM                                | is not set  |   kspp   | cut_attack_surface 
-------------------------------------------------------------------------------------------
```
  - `-m show_fail` for showing only the failed checks
  - `-m show_ok` for showing only the successful checks
  - `-m json` for printing the results in JSON format (for combining `kconfig-hardened-check` with other tools)

## Example output for `Fedora 34` kernel configuration
```
$ ./bin/kconfig-hardened-check -c /boot/config-5.19.14-200.fc36.x86_64 -l /proc/cmdline
[+] Kconfig file to check: /boot/config-5.19.14-200.fc36.x86_64
[+] Kernel cmdline file to check: /proc/cmdline
[+] Detected architecture: X86_64
[+] Detected kernel version: 5.19
[+] Detected compiler: GCC 120201
=========================================================================================================================
              option name               | type  |desired val | decision |      reason      | check result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_GCC_PLUGINS                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | FAIL: "is not set"
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= 5.5
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_MCE                          |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_MCE_INTEL                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_MCE_AMD                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_MICROCODE                        |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RETPOLINE                        |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_SMAP                         |kconfig|     y      |defconfig | self_protection  | OK: version >= 5.19
CONFIG_SYN_COOKIES                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_X86_UMIP                         |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_PAGE_TABLE_ISOLATION             |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOMIZE_MEMORY                 |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_INTEL_IOMMU                      |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_AMD_IOMMU                        |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_WX                         |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_LIST                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_WERROR                           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_IOMMU_DEFAULT_DMA_STRICT         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_IOMMU_DEFAULT_PASSTHROUGH        |kconfig| is not set |   kspp   | self_protection  | OK
CONFIG_ZERO_CALL_USED_REGS              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_HW_RANDOM_TPM                    |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_CORE                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RANDSTRUCT_PERFORMANCE           |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_RANDSTRUCT_FULL not "y"
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | OK: not found
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | OK: not found
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS not "y"
CONFIG_GCC_PLUGIN_STACKLEAK             |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_STACKLEAK_METRICS                |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK not "y"
CONFIG_STACKLEAK_RUNTIME_DISABLE        |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_GCC_PLUGIN_STACKLEAK not "y"
CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT  |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | FAIL: not found
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_CFI_CLANG not "y"
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   65536    |   kspp   | self_protection  | OK
CONFIG_INTEL_IOMMU_DEFAULT_ON           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLS                              |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_INTEL_IOMMU_SVM                  |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_AMD_IOMMU_V2                     |kconfig|     y      |   kspp   | self_protection  | FAIL: "m"
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |  clipos  | self_protection  | OK
CONFIG_SECURITY                         |kconfig|     y      |defconfig | security_policy  | OK
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | security_policy  | FAIL: "is not set"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: not found
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: not found
CONFIG_COMPAT_VDSO                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_VSYSCALL_NONE             |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PAGE_OWNER                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: not found
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_AIO                              |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_INTEL_TSX_MODE_OFF           |kconfig|     y      |  clipos  |cut_attack_surface| OK
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "m"
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |    my    |cut_attack_surface| FAIL: not found
CONFIG_MMIOTRACE                        |kconfig| is not set |    my    |cut_attack_surface| FAIL: "y"
CONFIG_LIVEPATCH                        |kconfig| is not set |    my    |cut_attack_surface| FAIL: "y"
CONFIG_IP_DCCP                          |kconfig| is not set |    my    |cut_attack_surface| OK
CONFIG_IP_SCTP                          |kconfig| is not set |    my    |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |    my    |cut_attack_surface| FAIL: "y"
CONFIG_VIDEO_VIVID                      |kconfig| is not set |    my    |cut_attack_surface| OK: not found
CONFIG_INPUT_EVBUG                      |kconfig| is not set |    my    |cut_attack_surface| OK
CONFIG_KGDB                             |kconfig| is not set |    my    |cut_attack_surface| FAIL: "y"
CONFIG_INTEGRITY                        |kconfig|     y      |defconfig | harden_userspace | OK
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     32     |  clipos  | harden_userspace | FAIL: "28"
nosmep                                  |cmdline| is not set |defconfig | self_protection  | OK: not found
nosmap                                  |cmdline| is not set |defconfig | self_protection  | OK: not found
nokaslr                                 |cmdline| is not set |defconfig | self_protection  | OK: not found
nopti                                   |cmdline| is not set |defconfig | self_protection  | OK: not found
nospectre_v1                            |cmdline| is not set |defconfig | self_protection  | OK: not found
nospectre_v2                            |cmdline| is not set |defconfig | self_protection  | OK: not found
rodata                                  |cmdline|     1      |defconfig | self_protection  | OK: rodata not found
init_on_alloc                           |cmdline|     1      |   kspp   | self_protection  | FAIL: not found
init_on_free                            |cmdline|     1      |   kspp   | self_protection  | FAIL: not found
slab_nomerge                            |cmdline|            |   kspp   | self_protection  | OK: CONFIG_SLAB_MERGE_DEFAULT "is not set"
iommu.strict                            |cmdline|     1      |   kspp   | self_protection  | FAIL: not found
iommu.passthrough                       |cmdline|     0      |   kspp   | self_protection  | OK: CONFIG_IOMMU_DEFAULT_PASSTHROUGH "is not set"
hardened_usercopy                       |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY "y"
slab_common.usercopy_fallback           |cmdline|     0      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY_FALLBACK not found
randomize_kstack_offset                 |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT "y"
pti                                     |cmdline|     on     |   kspp   | self_protection  | FAIL: not found
page_alloc.shuffle                      |cmdline|     1      |  clipos  | self_protection  | FAIL: not found
spectre_v2                              |cmdline|     on     |  clipos  | self_protection  | FAIL: not found
vsyscall                                |cmdline|    none    |   kspp   |cut_attack_surface| FAIL: not found
debugfs                                 |cmdline|    off     |  grsec   |cut_attack_surface| FAIL: not found

[+] Config check is finished: 'OK' - 101 / 'FAIL' - 101
```

## kconfig-hardened-check versioning

I usually update the kernel security hardening recommendations every few kernel releases.

So the version of `kconfig-hardened-check` is associated with the corresponding version of the kernel.

The version format is: __[major_number].[kernel_version].[kernel_patchlevel]__


## Questions and answers

__Q:__ How all these kernel parameters influence the Linux kernel security?

__A:__ To answer this question, you can use the `kconfig-hardened-check` [sources of recommendations][24]
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

__A:__ I personally don't support this recommendation because:
  - It decreases system safety (kernel oops is still not a rare situation)
  - It allows easier denial-of-service attacks for the whole system

I think having `CONFIG_BUG` is enough here.
If a kernel oops happens in the process context, the offending/attacking process is killed.
In other cases, the kernel panics, which is similar to `CONFIG_PANIC_ON_OOPS=y`.

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

__A:__ It means that your gcc doesn't support plugins. For example, if you have `gcc-7` on Ubuntu,
try to install `gcc-7-plugin-dev` package, it should help.


[1]: http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
[2]: https://docs.clip-os.org/clipos/kernel.html#configuration
[3]: https://grsecurity.net/
[4]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[5]: https://lwn.net/Articles/791863/
[6]: https://github.com/a13xp0p0v/kconfig-hardened-check/issues/38
[7]: https://github.com/BlackIkeEagle
[8]: https://blog.herecura.eu/blog/2020-05-30-kconfig-hardening-tests/
[9]: https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
[10]: https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
[11]: https://github.com/tych0/huldufolk
[12]: https://github.com/tych0
[13]: https://github.com/speed47/spectre-meltdown-checker
[14]: https://github.com/speed47
[15]: https://github.com/a13xp0p0v/kconfig-hardened-check/issues/53
[16]: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/54
[17]: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/62
[18]: https://cateee.net/lkddb/web-lkddb/
[19]: https://github.com/cateee/lkddb
[20]: https://kernel.org/
[21]: https://github.com/a13xp0p0v/kconfig-hardened-check/issues/66
[22]: https://github.com/a13xp0p0v/kconfig-hardened-check/issues/56
[23]: https://github.com/a13xp0p0v/kconfig-hardened-check/issues?q=label%3Akernel_maintainer_feedback
[24]: https://github.com/a13xp0p0v/kconfig-hardened-check#motivation
