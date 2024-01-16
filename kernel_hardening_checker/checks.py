#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

Author: Alexander Popov <alex.popov@linux.com>

This module contains knowledge for checks.
"""

# pylint: disable=missing-function-docstring,line-too-long,invalid-name
# pylint: disable=too-many-branches,too-many-statements,too-many-locals

from .engine import KconfigCheck, CmdlineCheck, SysctlCheck, VersionCheck, OR, AND


def add_kconfig_checks(l, arch):
    assert(arch), 'empty arch'

    # Calling the KconfigCheck class constructor:
    #     KconfigCheck(reason, decision, name, expected)
    #
    # [!] Don't add CmdlineChecks in add_kconfig_checks() to avoid wrong results
    #     when the tool doesn't check the cmdline.

    efi_not_set = KconfigCheck('-', '-', 'EFI', 'is not set')
    cc_is_gcc = KconfigCheck('-', '-', 'CC_IS_GCC', 'y') # exists since v4.18
    cc_is_clang = KconfigCheck('-', '-', 'CC_IS_CLANG', 'y') # exists since v4.18

    modules_not_set = KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set') # radical, but may be useful in some cases
    devmem_not_set = KconfigCheck('cut_attack_surface', 'kspp', 'DEVMEM', 'is not set') # refers to LOCKDOWN
    bpf_syscall_not_set = KconfigCheck('cut_attack_surface', 'lockdown', 'BPF_SYSCALL', 'is not set') # refers to LOCKDOWN

    # 'self_protection', 'defconfig'
    l += [KconfigCheck('self_protection', 'defconfig', 'BUG', 'y')]
    l += [KconfigCheck('self_protection', 'defconfig', 'SLUB_DEBUG', 'y')]
    l += [KconfigCheck('self_protection', 'defconfig', 'THREAD_INFO_IN_TASK', 'y')]
    gcc_plugins_support_is_set = KconfigCheck('self_protection', 'defconfig', 'GCC_PLUGINS', 'y')
    l += [gcc_plugins_support_is_set]
    iommu_support_is_set = KconfigCheck('self_protection', 'defconfig', 'IOMMU_SUPPORT', 'y')
    l += [iommu_support_is_set] # is needed for mitigating DMA attacks
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_REGULAR', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_AUTO', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR_STRONG', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STRICT_KERNEL_RWX', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'DEBUG_RODATA', 'y'))] # before v4.11
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'STRICT_MODULE_RWX', 'y'),
             KconfigCheck('self_protection', 'defconfig', 'DEBUG_SET_MODULE_RONX', 'y'),
             modules_not_set)] # DEBUG_SET_MODULE_RONX was before v4.11
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'REFCOUNT_FULL', 'y'),
             VersionCheck((5, 5)))] # REFCOUNT_FULL is enabled by default since v5.5
    l += [OR(KconfigCheck('self_protection', 'defconfig', 'INIT_STACK_ALL_ZERO', 'y'),
             KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y'))]
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y')]
    vmap_stack_is_set = KconfigCheck('self_protection', 'defconfig', 'VMAP_STACK', 'y')
    if arch in ('X86_64', 'ARM64', 'ARM'):
        l += [vmap_stack_is_set]
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'defconfig', 'SPECULATION_MITIGATIONS', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'DEBUG_WX', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'WERROR', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE_INTEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE_AMD', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RETPOLINE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'SYN_COOKIES', 'y')] # another reason?
        microcode_is_set = KconfigCheck('self_protection', 'defconfig', 'MICROCODE', 'y')
        l += [microcode_is_set] # is needed for mitigating CPU bugs
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MICROCODE_INTEL', 'y'),
                 AND(microcode_is_set,
                     VersionCheck((6, 6))))] # MICROCODE_INTEL was included in MICROCODE since v6.6
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MICROCODE_AMD', 'y'),
                 AND(microcode_is_set,
                     VersionCheck((6, 6))))] # MICROCODE_AMD was included in MICROCODE since v6.6
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_SMAP', 'y'),
                 VersionCheck((5, 19)))] # X86_SMAP is enabled by default since v5.19
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_UMIP', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'X86_INTEL_UMIP', 'y'))]
    if arch in ('ARM64', 'ARM'):
        l += [KconfigCheck('self_protection', 'defconfig', 'HW_RANDOM_TPM', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_DMA_STRICT', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set')] # true if IOMMU_DEFAULT_DMA_STRICT is set
        l += [KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR_PER_TASK', 'y')]
    if arch == 'X86_64':
        l += [KconfigCheck('self_protection', 'defconfig', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_MEMORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_KERNEL_IBT', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'CPU_SRSO', 'y')]
        l += [AND(KconfigCheck('self_protection', 'defconfig', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]
        l += [AND(KconfigCheck('self_protection', 'defconfig', 'AMD_IOMMU', 'y'),
                  iommu_support_is_set)]
    if arch == 'ARM64':
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_EPAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'UNMAP_KERNEL_AT_EL0', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_E0PD', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_PTR_AUTH_KERNEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_BTI_KERNEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MITIGATE_SPECTRE_BRANCH_HISTORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'ARM64_MTE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_MODULE_REGION_FULL', 'y')]
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'HARDEN_EL2_VECTORS', 'y'),
                 AND(KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y'),
                     VersionCheck((5, 9))))] # HARDEN_EL2_VECTORS was included in RANDOMIZE_BASE in v5.9
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_PREDICTOR', 'y'),
                 VersionCheck((5, 10)))] # HARDEN_BRANCH_PREDICTOR is enabled by default since v5.10
    if arch == 'ARM':
        l += [KconfigCheck('self_protection', 'defconfig', 'CPU_SW_DOMAIN_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_PREDICTOR', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_HISTORY', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'DEBUG_ALIGN_RODATA', 'y')]

    # 'self_protection', 'kspp'
    l += [KconfigCheck('self_protection', 'kspp', 'BUG_ON_DATA_CORRUPTION', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_HARDENED', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_RANDOM', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SHUFFLE_PAGE_ALLOCATOR', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'FORTIFY_SOURCE', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_LIST', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_VIRTUAL', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_SG', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_CREDENTIALS', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'STATIC_USERMODEHELPER', 'y')] # needs userspace support
    l += [KconfigCheck('self_protection', 'kspp', 'SCHED_CORE', 'y')]
    cfi_clang_is_set = KconfigCheck('self_protection', 'kspp', 'CFI_CLANG', 'y')
    cfi_clang_permissive_not_set = KconfigCheck('self_protection', 'kspp', 'CFI_PERMISSIVE', 'is not set')
    l += [OR(KconfigCheck('self_protection', 'kspp', 'DEBUG_NOTIFIERS', 'y'),
             AND(cfi_clang_is_set,
                 cfi_clang_permissive_not_set))]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'SCHED_STACK_END_CHECK', 'y'),
             vmap_stack_is_set)]
    kfence_is_set = KconfigCheck('self_protection', 'kspp', 'KFENCE', 'y')
    l += [kfence_is_set]
    l += [AND(KconfigCheck('self_protection', 'my', 'KFENCE_SAMPLE_INTERVAL', 'is not off'),
              kfence_is_set)]
    randstruct_is_set = OR(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_FULL', 'y'),
                           KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT', 'y'))
    l += [randstruct_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_PERFORMANCE', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set'),
              randstruct_is_set)]
    hardened_usercopy_is_set = KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y')
    l += [hardened_usercopy_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'),
              hardened_usercopy_is_set)] # usercopy whitelist violations should be prohibited
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_PAGESPAN', 'is not set'),
              hardened_usercopy_is_set)] # this debugging for HARDENED_USERCOPY is not needed for security
    l += [AND(KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_LATENT_ENTROPY', 'y'),
              gcc_plugins_support_is_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_ALL', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_SHA512', 'y'),
             modules_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'MODULE_SIG_FORCE', 'y'),
             modules_not_set)] # refers to LOCKDOWN
    l += [OR(KconfigCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
             KconfigCheck('self_protection', 'kspp', 'PAGE_POISONING_ZERO', 'y'))]
             # CONFIG_INIT_ON_FREE_DEFAULT_ON was added in v5.3.
             # CONFIG_PAGE_POISONING_ZERO was removed in v5.11.
             # Starting from v5.11 CONFIG_PAGE_POISONING unconditionally checks
             # the 0xAA poison pattern on allocation.
             # That brings higher performance penalty.
    l += [OR(KconfigCheck('self_protection', 'kspp', 'EFI_DISABLE_PCI_DMA', 'y'),
             efi_not_set)]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'RESET_ATTACK_MITIGATION', 'y'),
             efi_not_set)] # needs userspace support (systemd)
    ubsan_bounds_is_set = KconfigCheck('self_protection', 'kspp', 'UBSAN_BOUNDS', 'y')
    l += [ubsan_bounds_is_set]
    l += [OR(KconfigCheck('self_protection', 'kspp', 'UBSAN_LOCAL_BOUNDS', 'y'),
             AND(ubsan_bounds_is_set,
                 cc_is_gcc))]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'UBSAN_TRAP', 'y'),
              ubsan_bounds_is_set,
              KconfigCheck('self_protection', 'kspp', 'UBSAN_SHIFT', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_DIV_ZERO', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_UNREACHABLE', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_BOOL', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_ENUM', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'UBSAN_ALIGNMENT', 'is not set'))] # only array index bounds checking with traps
    l += [AND(KconfigCheck('self_protection', 'kspp', 'UBSAN_SANITIZE_ALL', 'y'),
              ubsan_bounds_is_set)]
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        stackleak_is_set = KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STACKLEAK', 'y')
        l += [AND(stackleak_is_set, gcc_plugins_support_is_set)]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'STACKLEAK_METRICS', 'is not set'),
                  stackleak_is_set,
                  gcc_plugins_support_is_set)]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'STACKLEAK_RUNTIME_DISABLE', 'is not set'),
                  stackleak_is_set,
                  gcc_plugins_support_is_set)]
        l += [KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT', 'y')]
    if arch in ('X86_64', 'ARM64'):
        l += [cfi_clang_is_set]
        l += [AND(cfi_clang_permissive_not_set,
                  cfi_clang_is_set)]
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'kspp', 'HW_RANDOM_TPM', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536')]
        l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set')] # true if IOMMU_DEFAULT_DMA_STRICT is set
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_DEFAULT_ON', 'y'),
                  iommu_support_is_set)]
    if arch in ('ARM64', 'ARM'):
        l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_WX', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'WERROR', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '32768')]
        l += [KconfigCheck('self_protection', 'kspp', 'SYN_COOKIES', 'y')] # another reason?
    if arch == 'X86_64':
        l += [KconfigCheck('self_protection', 'kspp', 'SLS', 'y')] # vs CVE-2021-26341 in Straight-Line-Speculation
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_SVM', 'y'),
                  iommu_support_is_set)]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'AMD_IOMMU_V2', 'y'),
                  iommu_support_is_set)]
    if arch == 'ARM64':
        l += [KconfigCheck('self_protection', 'kspp', 'ARM64_SW_TTBR0_PAN', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'SHADOW_CALL_STACK', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'KASAN_HW_TAGS', 'y')] # see also: kasan=on, kasan.stacktrace=off, kasan.fault=panic
    if arch == 'X86_32':
        l += [KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'HIGHMEM64G', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'X86_PAE', 'y')]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]

    # 'self_protection', 'clipos'
    l += [KconfigCheck('self_protection', 'clipos', 'SLAB_MERGE_DEFAULT', 'is not set')]

    # 'self_protection', 'my'
    l += [KconfigCheck('self_protection', 'my', 'LIST_HARDENED', 'y')]
    l += [KconfigCheck('self_protection', 'my', 'RANDOM_KMALLOC_CACHES', 'y')]

    # 'security_policy'
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [KconfigCheck('security_policy', 'defconfig', 'SECURITY', 'y')]
    if arch == 'ARM':
        l += [KconfigCheck('security_policy', 'kspp', 'SECURITY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_YAMA', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LANDLOCK', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DISABLE', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_BOOTPARAM', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DEVELOP', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LOCKDOWN_LSM', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LOCKDOWN_LSM_EARLY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_WRITABLE_HOOKS', 'is not set')] # refers to SECURITY_SELINUX_DISABLE
    l += [KconfigCheck('security_policy', 'my', 'SECURITY_SELINUX_DEBUG', 'is not set')]
    l += [OR(KconfigCheck('security_policy', 'my', 'SECURITY_SELINUX', 'y'),
             KconfigCheck('security_policy', 'my', 'SECURITY_APPARMOR', 'y'),
             KconfigCheck('security_policy', 'my', 'SECURITY_SMACK', 'y'),
             KconfigCheck('security_policy', 'my', 'SECURITY_TOMOYO', 'y'))] # one of major LSMs implementing MAC

    # 'cut_attack_surface', 'defconfig'
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP_FILTER', 'y')]
    l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'BPF_UNPRIV_DEFAULT_OFF', 'y'),
             bpf_syscall_not_set)] # see unprivileged_bpf_disabled
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)] # refers to LOCKDOWN
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('cut_attack_surface', 'defconfig', 'X86_INTEL_TSX_MODE_OFF', 'y')] # tsx=off

    # 'cut_attack_surface', 'kspp'
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'SECURITY_DMESG_RESTRICT', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'ACPI_CUSTOM_METHOD', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_BRK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'DEVKMEM', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'BINFMT_MISC', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'INET_DIAG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'KEXEC', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'PROC_KCORE', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_PTYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'HIBERNATION', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_X32', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_X32_ABI', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'MODIFY_LDT_SYSCALL', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'OABI_COMPAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_MSR', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_TIOCSTI', 'is not set')]
    l += [modules_not_set]
    l += [devmem_not_set]
    l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'IO_STRICT_DEVMEM', 'y'),
             devmem_not_set)] # refers to LOCKDOWN
    l += [AND(KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is not set'),
              KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is present'))]
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set')]
              # CONFIG_COMPAT_VDSO disabled ASLR of vDSO only on X86_64 and X86_32;
              # on ARM64 this option has different meaning
    if arch == 'X86_64':
        l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'X86_VSYSCALL_EMULATION', 'is not set'),
                 KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y'))]
                 # disabling X86_VSYSCALL_EMULATION turns vsyscall off completely,
                 # and LEGACY_VSYSCALL_NONE can be changed at boot time via the cmdline parameter
    if arch == 'ARM':
        l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)] # refers to LOCKDOWN

    # 'cut_attack_surface', 'grsec'
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'ZSMALLOC_STAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PAGE_OWNER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_KMEMLEAK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BINFMT_AOUT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KPROBE_EVENTS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'UPROBE_EVENTS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'GENERIC_TRACER', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'FUNCTION_TRACER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'STACK_TRACER', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'HIST_TRIGGERS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BLK_DEV_IO_TRACE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROC_VMCORE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROC_PAGE_MONITOR', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'USELIB', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'CHECKPOINT_RESTORE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'USERFAULTFD', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'HWPOISON_INJECT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MEM_SOFT_DIRTY', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEVPORT', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_FS', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'NOTIFIER_ERROR_INJECTION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'FAIL_FUTEX', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PUNIT_ATOM_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'ACPI_CONFIGFS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'EDAC_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DRM_I915_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'BCACHE_CLOSURES_DEBUG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'DVB_C8SECTPFE', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MTD_SLRAM', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'MTD_PHRAM', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'IO_URING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KCMP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'RSEQ', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'LATENCYTOP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'KCOV', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PROVIDE_OHCI1394_DMA_INIT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'SUNRPC_DEBUG', 'is not set')]
    l += [AND(KconfigCheck('cut_attack_surface', 'grsec', 'PTDUMP_DEBUGFS', 'is not set'),
              KconfigCheck('cut_attack_surface', 'grsec', 'X86_PTDUMP', 'is not set'))]

    # 'cut_attack_surface', 'maintainer'
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'DRM_LEGACY', 'is not set')] # recommended by Daniel Vetter in /issues/38
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'FB', 'is not set')] # recommended by Daniel Vetter in /issues/38
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'VT', 'is not set')] # recommended by Daniel Vetter in /issues/38
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD', 'is not set')] # recommended by Denis Efremov in /pull/54
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD_RAWCMD', 'is not set')] # recommended by Denis Efremov in /pull/62
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'NOUVEAU_LEGACY_CTX_SUPPORT', 'is not set')]
                                            # recommended by Dave Airlie in kernel commit b30a43ac7132cdda

    # 'cut_attack_surface', 'clipos'
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'STAGING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KSM', 'is not set')] # to prevent FLUSH+RELOAD attack
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KALLSYMS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KEXEC_FILE', 'is not set')] # refers to LOCKDOWN (permissive)
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'USER_NS', 'is not set')] # user.max_user_namespaces=0
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_CPUID', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_IOPL_IOPERM', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'ACPI_TABLE_UPGRADE', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'EFI_CUSTOM_SSDT_OVERLAYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'AIO', 'is not set')]
#   l += [KconfigCheck('cut_attack_surface', 'clipos', 'IKCONFIG', 'is not set')] # no, IKCONFIG is needed for this check :)

    # 'cut_attack_surface', 'lockdown'
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'EFI_TEST', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'MMIOTRACE_TEST', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'lockdown', 'KPROBES', 'is not set')] # refers to LOCKDOWN
    l += [bpf_syscall_not_set] # refers to LOCKDOWN

    # 'cut_attack_surface', 'my'
    l += [KconfigCheck('cut_attack_surface', 'my', 'MMIOTRACE', 'is not set')] # refers to LOCKDOWN (permissive)
    l += [KconfigCheck('cut_attack_surface', 'my', 'LIVEPATCH', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'IP_DCCP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'IP_SCTP', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'FTRACE', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'my', 'VIDEO_VIVID', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'INPUT_EVBUG', 'is not set')] # Can be used as a keylogger
    l += [KconfigCheck('cut_attack_surface', 'my', 'KGDB', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'CORESIGHT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'my', 'XFS_SUPPORT_V4', 'is not set')]
    l += [OR(KconfigCheck('cut_attack_surface', 'my', 'TRIM_UNUSED_KSYMS', 'y'),
             modules_not_set)]
    l += [KconfigCheck('cut_attack_surface', 'my', 'MODULE_FORCE_LOAD', 'is not set')]

    # 'harden_userspace'
    if arch == 'ARM64':
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_PTR_AUTH', 'y')]
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_BTI', 'y')]
    if arch in ('ARM', 'X86_32'):
        l += [KconfigCheck('harden_userspace', 'defconfig', 'VMSPLIT_3G', 'y')]
    l += [KconfigCheck('harden_userspace', 'clipos', 'COREDUMP', 'is not set')]
    l += [KconfigCheck('harden_userspace', 'my', 'ARCH_MMAP_RND_BITS', 'MAX')] # 'MAX' value is refined using ARCH_MMAP_RND_BITS_MAX


def add_cmdline_checks(l, arch):
    assert(arch), 'empty arch'

    # Calling the CmdlineCheck class constructor:
    #     CmdlineCheck(reason, decision, name, expected)
    #
    # [!] Don't add CmdlineChecks in add_kconfig_checks() to avoid wrong results
    #     when the tool doesn't check the cmdline.
    #
    # [!] Make sure that values of the options in CmdlineChecks need normalization.
    #     For more info see normalize_cmdline_options().
    #
    # A common pattern for checking the 'param_x' cmdline parameter
    # that __overrides__ the 'PARAM_X_DEFAULT' kconfig option:
    #   l += [OR(CmdlineCheck(reason, decision, 'param_x', '1'),
    #            AND(KconfigCheck(reason, decision, 'PARAM_X_DEFAULT_ON', 'y'),
    #                CmdlineCheck(reason, decision, 'param_x, 'is not set')))]
    #
    # Here we don't check the kconfig options or minimal kernel version
    # required for the cmdline parameters. That would make the checks
    # very complex and not give a 100% guarantee anyway.

    # 'self_protection', 'defconfig'
    l += [CmdlineCheck('self_protection', 'defconfig', 'nosmep', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nosmap', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nokaslr', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nopti', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_v1', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_v2', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospectre_bhb', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospec_store_bypass_disable', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'dis_ucode_ldr', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nobti', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nopauth', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nomte', 'is not set')]
    if arch in ('X86_64', 'X86_32'):
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'spectre_v2', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2_user', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'spectre_v2_user', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spec_store_bypass_disable', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'spec_store_bypass_disable', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'l1tf', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'l1tf', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mds', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'mds', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'tsx_async_abort', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'tsx_async_abort', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'srbds', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'srbds', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mmio_stale_data', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'mmio_stale_data', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'retbleed', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'retbleed', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spec_rstack_overflow', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'spec_rstack_overflow', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'gather_data_sampling', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'gather_data_sampling', 'is not set')))]
    if arch == 'ARM64':
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'kpti', 'is not off'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'kpti', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'ssbd', 'kernel'),
                 CmdlineCheck('self_protection', 'my', 'ssbd', 'force-on'),
                 AND(CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt'),
                     CmdlineCheck('self_protection', 'defconfig', 'ssbd', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'full'),
                 AND(KconfigCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y'),
                     CmdlineCheck('self_protection', 'defconfig', 'rodata', 'is not set')))]
    else:
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'on'),
                 CmdlineCheck('self_protection', 'defconfig', 'rodata', 'is not set'))]

    # 'self_protection', 'kspp'
    l += [CmdlineCheck('self_protection', 'kspp', 'mitigations', 'auto,nosmt')]
    l += [CmdlineCheck('self_protection', 'kspp', 'slab_merge', 'is not set')] # consequence of 'slab_nomerge' by kspp
    l += [CmdlineCheck('self_protection', 'kspp', 'slub_merge', 'is not set')] # consequence of 'slab_nomerge' by kspp
    l += [CmdlineCheck('self_protection', 'kspp', 'page_alloc.shuffle', '1')]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'slab_nomerge', 'is present'),
             AND(KconfigCheck('self_protection', 'clipos', 'SLAB_MERGE_DEFAULT', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slab_merge', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slub_merge', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_alloc', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'init_on_alloc', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_free', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'init_on_free', 'is not set')),
             AND(CmdlineCheck('self_protection', 'kspp', 'page_poison', '1'),
                 KconfigCheck('self_protection', 'kspp', 'PAGE_POISONING_ZERO', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'slub_debug', 'P')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'hardened_usercopy', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'hardened_usercopy', 'is not set')))]
    l += [AND(CmdlineCheck('self_protection', 'kspp', 'slab_common.usercopy_fallback', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'))]
              # Consequence of the HARDENED_USERCOPY_FALLBACK check by kspp.
              # Don't require slab_common.usercopy_fallback=0,
              # since HARDENED_USERCOPY_FALLBACK was removed in Linux v5.16.
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'iommu.strict', '1'),
                 AND(KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y'),
                     CmdlineCheck('self_protection', 'kspp', 'iommu.strict', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'iommu.passthrough', '0'),
                 AND(KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set'),
                     CmdlineCheck('self_protection', 'kspp', 'iommu.passthrough', 'is not set')))]
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'randomize_kstack_offset', '1'),
                 AND(KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT', 'y'),
                     CmdlineCheck('self_protection', 'kspp', 'randomize_kstack_offset', 'is not set')))]
    if arch in ('X86_64', 'X86_32'):
        l += [AND(CmdlineCheck('self_protection', 'kspp', 'pti', 'on'),
                  CmdlineCheck('self_protection', 'defconfig', 'nopti', 'is not set'))]

    # 'self_protection', 'clipos'
    if arch in ('X86_64', 'X86_32'):
        l += [CmdlineCheck('self_protection', 'clipos', 'iommu', 'force')]

    # 'self_protection', 'my'
    l += [OR(CmdlineCheck('self_protection', 'my', 'kfence.sample_interval', 'is not off'),
             AND(KconfigCheck('self_protection', 'my', 'KFENCE_SAMPLE_INTERVAL', 'is not off'),
                 CmdlineCheck('self_protection', 'my', 'kfence.sample_interval', 'is not set')))]

    # 'cut_attack_surface', 'defconfig'
    if arch in ('X86_64', 'X86_32'):
        l += [OR(CmdlineCheck('cut_attack_surface', 'defconfig', 'tsx', 'off'),
                 AND(KconfigCheck('cut_attack_surface', 'defconfig', 'X86_INTEL_TSX_MODE_OFF', 'y'),
                     CmdlineCheck('cut_attack_surface', 'defconfig', 'tsx', 'is not set')))]

    # 'cut_attack_surface', 'kspp'
    l += [CmdlineCheck('cut_attack_surface', 'kspp', 'nosmt', 'is present')] # slow (high performance penalty)
    if arch == 'X86_64':
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vsyscall', 'none'),
                 KconfigCheck('cut_attack_surface', 'kspp', 'X86_VSYSCALL_EMULATION', 'is not set'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y'),
                     CmdlineCheck('cut_attack_surface', 'kspp', 'vsyscall', 'is not set')))]
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vdso32', '0'),
                 CmdlineCheck('cut_attack_surface', 'my', 'vdso32', '1'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set'),
                     CmdlineCheck('cut_attack_surface', 'my', 'vdso32', 'is not set')))] # the vdso32 parameter must not be 2
    if arch == 'X86_32':
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vdso32', '0'),
                 CmdlineCheck('cut_attack_surface', 'my', 'vdso', '0'),
                 CmdlineCheck('cut_attack_surface', 'my', 'vdso32', '1'),
                 CmdlineCheck('cut_attack_surface', 'my', 'vdso', '1'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set'),
                     CmdlineCheck('cut_attack_surface', 'my', 'vdso32', 'is not set'),
                     CmdlineCheck('cut_attack_surface', 'my', 'vdso', 'is not set')))] # the vdso and vdso32 parameters must not be 2

    # 'cut_attack_surface', 'grsec'
    # The cmdline checks compatible with the kconfig options disabled by grsecurity...
    l += [OR(CmdlineCheck('cut_attack_surface', 'grsec', 'debugfs', 'off'),
             KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_FS', 'is not set'))] # ... the end

    # 'cut_attack_surface', 'my'
    l += [CmdlineCheck('cut_attack_surface', 'my', 'sysrq_always_enabled', 'is not set')]

    # 'harden_userspace'
    l += [CmdlineCheck('harden_userspace', 'defconfig', 'norandmaps', 'is not set')]


no_kstrtobool_options = [
    'debugfs', # See debugfs_kernel() in fs/debugfs/inode.c
    'mitigations', # See mitigations_parse_cmdline() in kernel/cpu.c
    'pti', # See pti_check_boottime_disable() in arch/x86/mm/pti.c
    'spectre_v2', # See spectre_v2_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'spectre_v2_user', # See spectre_v2_parse_user_cmdline() in arch/x86/kernel/cpu/bugs.c
    'spec_store_bypass_disable', # See ssb_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'l1tf', # See l1tf_cmdline() in arch/x86/kernel/cpu/bugs.c
    'mds', # See mds_cmdline() in arch/x86/kernel/cpu/bugs.c
    'tsx_async_abort', # See tsx_async_abort_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'srbds', # See srbds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'mmio_stale_data', # See mmio_stale_data_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'retbleed', # See retbleed_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'rodata', # See set_debug_rodata() in init/main.c
    'ssbd', # See parse_spectre_v4_param() in arch/arm64/kernel/proton-pack.c
    'spec_rstack_overflow', # See srso_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'gather_data_sampling', # See gds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
    'slub_debug', # See setup_slub_debug() in mm/slub.c
    'iommu', # See iommu_setup() in arch/x86/kernel/pci-dma.c
    'vsyscall', # See vsyscall_setup() in arch/x86/entry/vsyscall/vsyscall_64.c
    'vdso32', # See vdso32_setup() in arch/x86/entry/vdso/vdso32-setup.c
    'vdso', # See vdso32_setup() in arch/x86/entry/vdso/vdso32-setup.c
    'tsx' # See tsx_init() in arch/x86/kernel/cpu/tsx.c
]


def normalize_cmdline_options(option, value):
    # Don't normalize the cmdline option values if
    # the Linux kernel doesn't use kstrtobool() for them
    if option in no_kstrtobool_options:
        return value

    # Implement a limited part of the kstrtobool() logic
    if value.lower() in ('1', 'on', 'y', 'yes', 't', 'true'):
        return '1'
    if value.lower() in ('0', 'off', 'n', 'no', 'f', 'false'):
        return '0'

    # Preserve unique values
    return value


# TODO: draft of security hardening sysctls:
#    what about bpf_jit_enable?
#    vm.mmap_min_addr has a good value
#    nosmt sysfs control file
#    vm.mmap_rnd_bits=max (?)
#    kernel.sysrq=0
#    abi.vsyscall32 (any value except 2)
#    kernel.oops_limit (think about a proper value)
#    kernel.warn_limit (think about a proper value)
#    net.ipv4.tcp_syncookies=1 (?)

def add_sysctl_checks(l, _arch):
# This function may be called with arch=None

# Calling the SysctlCheck class constructor:
#   SysctlCheck(reason, decision, name, expected)

    l += [SysctlCheck('self_protection', 'kspp', 'net.core.bpf_jit_harden', '2')]

    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.dmesg_restrict', '1')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.perf_event_paranoid', '3')] # with a custom patch, see https://lwn.net/Articles/696216/
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.kexec_load_disabled', '1')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'user.max_user_namespaces', '0')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'dev.tty.ldisc_autoload', '0')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.unprivileged_bpf_disabled', '1')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'kernel.kptr_restrict', '2')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'dev.tty.legacy_tiocsti', '0')]
    l += [SysctlCheck('cut_attack_surface', 'kspp', 'vm.unprivileged_userfaultfd', '0')]
          # At first, it disabled unprivileged userfaultfd,
          # and since v5.11 it enables unprivileged userfaultfd for user-mode only.

    l += [SysctlCheck('cut_attack_surface', 'clipos', 'kernel.modules_disabled', '1')] # radical, but may be useful in some cases

    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_symlinks', '1')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_hardlinks', '1')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_fifos', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.protected_regular', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'fs.suid_dumpable', '0')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'kernel.randomize_va_space', '2')]
    l += [SysctlCheck('harden_userspace', 'kspp', 'kernel.yama.ptrace_scope', '3')]
