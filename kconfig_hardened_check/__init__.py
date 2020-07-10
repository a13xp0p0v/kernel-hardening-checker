#!/usr/bin/python3

#
# This tool helps me to check the Linux kernel Kconfig option list
# against my hardening preferences for X86_64, ARM64, X86_32, and ARM.
# Let the computers do their job!
#
# Author: Alexander Popov <alex.popov@linux.com>
#
# Please don't cry if my Python code looks like C.
#
#
# N.B Hardening command line parameters:
#    slub_debug=FZP
#    slab_nomerge
#    page_alloc.shuffle=1
#    iommu=force (does it help against DMA attacks?)
#    page_poison=1 (if enabled)
#    init_on_alloc=1
#    init_on_free=1
#    loadpin.enforce=1
#
#    Mitigations of CPU vulnerabilities:
#       Аrch-independent:
#           mitigations=auto,nosmt
#       X86:
#           spectre_v2=on
#           pti=on
#           spec_store_bypass_disable=on
#           l1tf=full,force
#           mds=full,nosmt
#           tsx=off
#       ARM64:
#           kpti=on
#           ssbd=force-on
#
# N.B. Hardening sysctls:
#    kernel.kptr_restrict=2
#    kernel.dmesg_restrict=1
#    kernel.perf_event_paranoid=3
#    kernel.kexec_load_disabled=1
#    kernel.yama.ptrace_scope=3
#    user.max_user_namespaces=0
#    kernel.unprivileged_bpf_disabled=1
#    net.core.bpf_jit_harden=2
#
#    vm.unprivileged_userfaultfd=0
#
#    dev.tty.ldisc_autoload=0
#    fs.protected_symlinks=1
#    fs.protected_hardlinks=1
#    fs.protected_fifos=2
#    fs.protected_regular=2
#    fs.suid_dumpable=0
#    kernel.modules_disabled=1

import sys
from argparse import ArgumentParser
from collections import OrderedDict
import re
import json
from .__about__ import __version__

# pylint: disable=line-too-long,bad-whitespace,too-many-branches
# pylint: disable=too-many-statements,global-statement

# debug_mode enables:
#    - reporting about unknown kernel options in the config,
#    - verbose printing of ComplexOptChecks (OR, AND).
debug_mode = False

# json_mode is for printing results in JSON format
json_mode = False

supported_archs = ['X86_64', 'X86_32', 'ARM64', 'ARM']

kernel_version = None


class OptCheck:
    def __init__(self, reason, decision, name, expected):
        self.name = name
        self.expected = expected
        self.decision = decision
        self.reason = reason
        self.state = None
        self.result = None

    def check(self):
        if self.expected == self.state:
            self.result = 'OK'
        elif self.state is None:
            if self.expected == 'is not set':
                self.result = 'OK: not found'
            else:
                self.result = 'FAIL: not found'
        else:
            self.result = 'FAIL: "' + self.state + '"'

        if self.result.startswith('OK'):
            return True
        return False

    def table_print(self, with_results):
        print('CONFIG_{:<38}|{:^13}|{:^10}|{:^20}'.format(self.name, self.expected, self.decision, self.reason), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class VerCheck:
    def __init__(self, ver_expected):
        self.ver_expected = ver_expected
        self.result = None

    def check(self):
        if kernel_version[0] > self.ver_expected[0]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return True
        if kernel_version[0] < self.ver_expected[0]:
            self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return False
        if kernel_version[1] >= self.ver_expected[1]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return True
        self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
        return False

    def table_print(self, with_results):
        ver_req = 'kernel version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
        print('{:<91}'.format(ver_req), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class PresenceCheck:
    def __init__(self, name):
        self.name = name
        self.state = None
        self.result = None

    def check(self):
        if self.state is None:
            self.result = 'FAIL: not present'
            return False
        self.result = 'OK: is present'
        return True

    def table_print(self, with_results):
        print('CONFIG_{:<84}'.format(self.name + ' is present'), end='')
        if with_results:
            print('|   {}'.format(self.result), end='')


class ComplexOptCheck:
    def __init__(self, *opts):
        self.opts = opts
        self.result = None

    @property
    def name(self):
        return self.opts[0].name

    @property
    def expected(self):
        return self.opts[0].expected

    @property
    def decision(self):
        return self.opts[0].decision

    @property
    def reason(self):
        return self.opts[0].reason

    def table_print(self, with_results):
        if debug_mode:
            print('    {:87}'.format('<<< ' + self.__class__.__name__ + ' >>>'), end='')
            if with_results:
                print('|   {}'.format(self.result), end='')
            for o in self.opts:
                print()
                o.table_print(with_results)
        else:
            o = self.opts[0]
            o.table_print(False)
            if with_results:
                print('|   {}'.format(self.result), end='')


class OR(ComplexOptCheck):
    # self.opts[0] is the option that this OR-check is about.
    # Use case:
    #     OR(<X_is_hardened>, <X_is_disabled>)
    #     OR(<X_is_hardened>, <X_is_hardened_old>)

    def check(self):
        if not self.opts:
            sys.exit('[!] ERROR: invalid OR check')

        for i, opt in enumerate(self.opts):
            ret = opt.check()
            if ret:
                if i == 0 or not hasattr(opt, 'expected'):
                    self.result = opt.result
                else:
                    self.result = 'OK: CONFIG_{} "{}"'.format(opt.name, opt.expected)
                return True
        self.result = self.opts[0].result
        return False


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use case: AND(<suboption>, <main_option>)
    # Suboption is not checked if checking of the main_option is failed.

    def check(self):
        for i, opt in reversed(list(enumerate(self.opts))):
            ret = opt.check()
            if i == 0:
                self.result = opt.result
                return ret
            if not ret:
                if hasattr(opt, 'expected'):
                    self.result = 'FAIL: CONFIG_{} is needed'.format(opt.name)
                else:
                    self.result = opt.result
                return False

        sys.exit('[!] ERROR: invalid AND check')


def detect_arch(fname):
    with open(fname, 'r') as f:
        arch_pattern = re.compile("CONFIG_[a-zA-Z0-9_]*=y")
        arch = None
        if not json_mode:
            print('[+] Trying to detect architecture in "{}"...'.format(fname))
        for line in f.readlines():
            if arch_pattern.match(line):
                option, _ = line[7:].split('=', 1)
                if option in supported_archs:
                    if not arch:
                        arch = option
                    else:
                        return None, 'more than one supported architecture is detected'
        if not arch:
            return None, 'failed to detect architecture'
        return arch, 'OK'


def detect_version(fname):
    with open(fname, 'r') as f:
        ver_pattern = re.compile("# Linux/.* Kernel Configuration")
        if not json_mode:
            print('[+] Trying to detect kernel version in "{}"...'.format(fname))
        for line in f.readlines():
            if ver_pattern.match(line):
                line = line.strip()
                if not json_mode:
                    print('[+] Found version line: "{}"'.format(line))
                parts = line.split()
                ver_str = parts[2]
                ver_numbers = ver_str.split('.')
                if len(ver_numbers) < 3 or not ver_numbers[0].isdigit() or not ver_numbers[1].isdigit():
                    msg = 'failed to parse the version "' + ver_str + '"'
                    return None, msg
                return (int(ver_numbers[0]), int(ver_numbers[1])), None
        return None, 'no kernel version detected'


def construct_checklist(l, arch):
    modules_not_set = OptCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set')
    devmem_not_set = OptCheck('cut_attack_surface', 'kspp', 'DEVMEM', 'is not set') # refers to LOCKDOWN

    # 'self_protection', 'defconfig'
    l += [OptCheck('self_protection', 'defconfig', 'BUG', 'y')]
    l += [OptCheck('self_protection', 'defconfig', 'SLUB_DEBUG', 'y')]
    l += [OptCheck('self_protection', 'defconfig', 'GCC_PLUGINS', 'y')]
    l += [OR(OptCheck('self_protection', 'defconfig', 'STACKPROTECTOR_STRONG', 'y'),
             OptCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
    l += [OR(OptCheck('self_protection', 'defconfig', 'STRICT_KERNEL_RWX', 'y'),
             OptCheck('self_protection', 'defconfig', 'DEBUG_RODATA', 'y'))] # before v4.11
    l += [OR(OptCheck('self_protection', 'defconfig', 'STRICT_MODULE_RWX', 'y'),
             OptCheck('self_protection', 'defconfig', 'DEBUG_SET_MODULE_RONX', 'y'),
             modules_not_set)] # DEBUG_SET_MODULE_RONX was before v4.11
    l += [OR(OptCheck('self_protection', 'defconfig', 'REFCOUNT_FULL', 'y'),
             VerCheck((5, 5)))] # REFCOUNT_FULL is enabled by default since v5.5
    iommu_support_is_set = OptCheck('self_protection', 'defconfig', 'IOMMU_SUPPORT', 'y')
    l += [iommu_support_is_set] # is needed for mitigating DMA attacks
    if arch in ('X86_64', 'X86_32'):
        l += [OptCheck('self_protection', 'defconfig', 'MICROCODE', 'y')] # is needed for mitigating CPU bugs
        l += [OptCheck('self_protection', 'defconfig', 'RETPOLINE', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'X86_SMAP', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'SYN_COOKIES', 'y')] # another reason?
        l += [OR(OptCheck('self_protection', 'defconfig', 'X86_UMIP', 'y'),
                 OptCheck('self_protection', 'defconfig', 'X86_INTEL_UMIP', 'y'))]
    if arch == 'X86_64':
        l += [OptCheck('self_protection', 'defconfig', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'RANDOMIZE_MEMORY', 'y')]
        l += [AND(OptCheck('self_protection', 'defconfig', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]
        l += [AND(OptCheck('self_protection', 'defconfig', 'AMD_IOMMU', 'y'),
                  iommu_support_is_set)]
    if arch == 'ARM64':
        l += [OptCheck('self_protection', 'defconfig', 'ARM64_PAN', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'UNMAP_KERNEL_AT_EL0', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'HARDEN_EL2_VECTORS', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'ARM64_PTR_AUTH', 'y')]
    if arch in ('X86_64', 'ARM64'):
        l += [OptCheck('self_protection', 'defconfig', 'VMAP_STACK', 'y')]
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OptCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'THREAD_INFO_IN_TASK', 'y')]
    if arch == 'ARM':
        l += [OptCheck('self_protection', 'defconfig', 'CPU_SW_DOMAIN_PAN', 'y')]
        l += [OptCheck('self_protection', 'defconfig', 'STACKPROTECTOR_PER_TASK', 'y')]
    if arch in ('ARM64', 'ARM'):
        l += [OptCheck('self_protection', 'defconfig', 'HARDEN_BRANCH_PREDICTOR', 'y')]

    # 'self_protection', 'kspp'
    l += [OptCheck('self_protection', 'kspp', 'BUG_ON_DATA_CORRUPTION', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'DEBUG_WX', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'SCHED_STACK_END_CHECK', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'SLAB_FREELIST_HARDENED', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'SLAB_FREELIST_RANDOM', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'SHUFFLE_PAGE_ALLOCATOR', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'FORTIFY_SOURCE', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'DEBUG_LIST', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'DEBUG_SG', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'DEBUG_CREDENTIALS', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'DEBUG_NOTIFIERS', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y')]
    l += [OptCheck('self_protection', 'kspp', 'GCC_PLUGIN_LATENT_ENTROPY', 'y')]
    randstruct_is_set = OptCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT', 'y')
    l += [randstruct_is_set]
    hardened_usercopy_is_set = OptCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y')
    l += [hardened_usercopy_is_set]
    l += [AND(OptCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'),
              hardened_usercopy_is_set)]
    l += [OR(OptCheck('self_protection', 'kspp', 'MODULE_SIG', 'y'),
             modules_not_set)]
    l += [OR(OptCheck('self_protection', 'kspp', 'MODULE_SIG_ALL', 'y'),
             modules_not_set)]
    l += [OR(OptCheck('self_protection', 'kspp', 'MODULE_SIG_SHA512', 'y'),
             modules_not_set)]
    l += [OR(OptCheck('self_protection', 'kspp', 'MODULE_SIG_FORCE', 'y'),
             modules_not_set)] # refers to LOCKDOWN
    l += [OR(OptCheck('self_protection', 'kspp', 'INIT_STACK_ALL', 'y'),
             OptCheck('self_protection', 'kspp', 'GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y'))]
    l += [OR(OptCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
             OptCheck('self_protection', 'kspp', 'PAGE_POISONING', 'y'))] # before v5.3
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        stackleak_is_set = OptCheck('self_protection', 'kspp', 'GCC_PLUGIN_STACKLEAK', 'y')
        l += [stackleak_is_set]
    if arch in ('X86_64', 'X86_32'):
        l += [OptCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536')]
    if arch == 'X86_32':
        l += [OptCheck('self_protection', 'kspp', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [OptCheck('self_protection', 'kspp', 'HIGHMEM64G', 'y')]
        l += [OptCheck('self_protection', 'kspp', 'X86_PAE', 'y')]
    if arch == 'ARM64':
        l += [OptCheck('self_protection', 'kspp', 'ARM64_SW_TTBR0_PAN', 'y')]
    if arch in ('ARM64', 'ARM'):
        l += [OptCheck('self_protection', 'kspp', 'SYN_COOKIES', 'y')] # another reason?
        l += [OptCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '32768')]

    # 'self_protection', 'clipos'
    l += [OptCheck('self_protection', 'clipos', 'SECURITY_DMESG_RESTRICT', 'y')]
    l += [OptCheck('self_protection', 'clipos', 'DEBUG_VIRTUAL', 'y')]
    l += [OptCheck('self_protection', 'clipos', 'STATIC_USERMODEHELPER', 'y')] # needs userspace support
    l += [OptCheck('self_protection', 'clipos', 'SLAB_MERGE_DEFAULT', 'is not set')] # slab_nomerge
    l += [OptCheck('self_protection', 'clipos', 'RANDOM_TRUST_BOOTLOADER', 'is not set')]
    l += [OptCheck('self_protection', 'clipos', 'RANDOM_TRUST_CPU', 'is not set')]
    l += [AND(OptCheck('self_protection', 'clipos', 'GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set'),
              randstruct_is_set)]
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [AND(OptCheck('self_protection', 'clipos', 'STACKLEAK_METRICS', 'is not set'),
                  stackleak_is_set)]
        l += [AND(OptCheck('self_protection', 'clipos', 'STACKLEAK_RUNTIME_DISABLE', 'is not set'),
                  stackleak_is_set)]
    if arch in ('X86_64', 'X86_32'):
        l += [AND(OptCheck('self_protection', 'clipos', 'INTEL_IOMMU_SVM', 'y'),
                  iommu_support_is_set)]
        l += [AND(OptCheck('self_protection', 'clipos', 'INTEL_IOMMU_DEFAULT_ON', 'y'),
                  iommu_support_is_set)]
    if arch == 'X86_32':
        l += [AND(OptCheck('self_protection', 'clipos', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]

    # 'self_protection', 'my'
    l += [OptCheck('self_protection', 'my', 'SLUB_DEBUG_ON', 'y')]
    l += [OptCheck('self_protection', 'my', 'RESET_ATTACK_MITIGATION', 'y')] # needs userspace support (systemd)
    if arch == 'X86_64':
        l += [AND(OptCheck('self_protection', 'my', 'AMD_IOMMU_V2', 'y'),
                  iommu_support_is_set)]

    # 'security_policy'
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OptCheck('security_policy', 'defconfig', 'SECURITY', 'y')] # and choose your favourite LSM
    if arch == 'ARM':
        l += [OptCheck('security_policy', 'kspp', 'SECURITY', 'y')] # and choose your favourite LSM
    l += [OptCheck('security_policy', 'kspp', 'SECURITY_YAMA', 'y')]
    l += [OR(OptCheck('security_policy', 'my', 'SECURITY_WRITABLE_HOOKS', 'is not set'),
             OptCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DISABLE', 'is not set'))]
    l += [OptCheck('security_policy', 'clipos', 'SECURITY_LOCKDOWN_LSM', 'y')]
    l += [OptCheck('security_policy', 'clipos', 'SECURITY_LOCKDOWN_LSM_EARLY', 'y')]
    l += [OptCheck('security_policy', 'clipos', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y')]
    l += [OptCheck('security_policy', 'my', 'SECURITY_SAFESETID', 'y')]
    loadpin_is_set = OptCheck('security_policy', 'my', 'SECURITY_LOADPIN', 'y')
    l += [loadpin_is_set] # needs userspace support
    l += [AND(OptCheck('security_policy', 'my', 'SECURITY_LOADPIN_ENFORCE', 'y'),
              loadpin_is_set)]

    # 'cut_attack_surface', 'defconfig'
    l += [OptCheck('cut_attack_surface', 'defconfig', 'SECCOMP', 'y')]
    l += [OptCheck('cut_attack_surface', 'defconfig', 'SECCOMP_FILTER', 'y')]
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OR(OptCheck('cut_attack_surface', 'defconfig', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)] # refers to LOCKDOWN

    # 'cut_attack_surface', 'kspp'
    l += [OptCheck('cut_attack_surface', 'kspp', 'ACPI_CUSTOM_METHOD', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'kspp', 'COMPAT_BRK', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'DEVKMEM', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'BINFMT_MISC', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'INET_DIAG', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'KEXEC', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'kspp', 'PROC_KCORE', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'kspp', 'LEGACY_PTYS', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'HIBERNATION', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'X86_X32', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'MODIFY_LDT_SYSCALL', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'kspp', 'OABI_COMPAT', 'is not set')]
    l += [modules_not_set]
    l += [devmem_not_set]
    l += [OR(OptCheck('cut_attack_surface', 'kspp', 'IO_STRICT_DEVMEM', 'y'),
             devmem_not_set)] # refers to LOCKDOWN
    if arch == 'ARM':
        l += [OR(OptCheck('cut_attack_surface', 'kspp', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)] # refers to LOCKDOWN
    if arch == 'X86_64':
        l += [OptCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y')] # 'vsyscall=none'

    # 'cut_attack_surface', 'grsecurity'
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'X86_PTDUMP', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'ZSMALLOC_STAT', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'PAGE_OWNER', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'DEBUG_KMEMLEAK', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'BINFMT_AOUT', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'KPROBES', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'UPROBES', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'GENERIC_TRACER', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'PROC_VMCORE', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'PROC_PAGE_MONITOR', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'USELIB', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'CHECKPOINT_RESTORE', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'USERFAULTFD', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'HWPOISON_INJECT', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'MEM_SOFT_DIRTY', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'DEVPORT', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'DEBUG_FS', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'grsecurity', 'NOTIFIER_ERROR_INJECTION','is not set')]

    # 'cut_attack_surface', 'maintainer'
    l += [OptCheck('cut_attack_surface', 'maintainer', 'DRM_LEGACY', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'maintainer', 'FB', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'maintainer', 'VT', 'is not set')]

    # 'cut_attack_surface', 'lockdown'
    l += [OptCheck('cut_attack_surface', 'lockdown', 'ACPI_TABLE_UPGRADE', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'lockdown', 'X86_IOPL_IOPERM', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'lockdown', 'EFI_TEST', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'lockdown', 'BPF_SYSCALL', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'lockdown', 'MMIOTRACE_TEST', 'is not set')] # refers to LOCKDOWN

    # 'cut_attack_surface', 'clipos'
    l += [OptCheck('cut_attack_surface', 'clipos', 'STAGING', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'clipos', 'KSM', 'is not set')] # to prevent FLUSH+RELOAD attack
#   l += [OptCheck('cut_attack_surface', 'clipos', 'IKCONFIG', 'is not set')] # no, IKCONFIG is needed for this check :)
    l += [OptCheck('cut_attack_surface', 'clipos', 'KALLSYMS', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'clipos', 'X86_VSYSCALL_EMULATION', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'clipos', 'KEXEC_FILE', 'is not set')] # refers to LOCKDOWN (permissive)
    l += [OptCheck('cut_attack_surface', 'clipos', 'USER_NS', 'is not set')] # user.max_user_namespaces=0
    l += [OptCheck('cut_attack_surface', 'clipos', 'X86_MSR', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'clipos', 'X86_CPUID', 'is not set')]
    l += [AND(OptCheck('cut_attack_surface', 'clipos', 'LDISC_AUTOLOAD', 'is not set'),
              PresenceCheck('LDISC_AUTOLOAD'))]
    if arch in ('X86_64', 'X86_32'):
        l += [OptCheck('cut_attack_surface', 'clipos', 'X86_INTEL_TSX_MODE_OFF', 'y')] # tsx=off

    # 'cut_attack_surface', 'grapheneos'
    l += [OptCheck('cut_attack_surface', 'grapheneos', 'AIO', 'is not set')]

    # 'cut_attack_surface', 'my'
    l += [OptCheck('cut_attack_surface', 'my', 'MMIOTRACE', 'is not set')] # refers to LOCKDOWN (permissive)
    l += [OptCheck('cut_attack_surface', 'my', 'LIVEPATCH', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'my', 'IP_DCCP', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'my', 'IP_SCTP', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'my', 'FTRACE', 'is not set')] # refers to LOCKDOWN
    l += [OptCheck('cut_attack_surface', 'my', 'BPF_JIT', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'my', 'VIDEO_VIVID', 'is not set')]
    l += [OptCheck('cut_attack_surface', 'my', 'INPUT_EVBUG', 'is not set')] # Can be used as a keylogger

    # 'userspace_hardening'
    l += [OptCheck('userspace_hardening', 'defconfig', 'INTEGRITY', 'y')]
    if arch in ('ARM', 'X86_32'):
        l += [OptCheck('userspace_hardening', 'defconfig', 'VMSPLIT_3G', 'y')]
    if arch in ('X86_64', 'ARM64'):
        l += [OptCheck('userspace_hardening', 'clipos', 'ARCH_MMAP_RND_BITS', '32')]
    if arch in ('X86_32', 'ARM'):
        l += [OptCheck('userspace_hardening', 'my', 'ARCH_MMAP_RND_BITS', '16')]

#   l += [OptCheck('feature_test', 'my', 'LKDTM', 'm')] # only for debugging!


def print_checklist(checklist, with_results):
    if json_mode:
        opts = []
        for o in checklist:
            opt = ['CONFIG_'+o.name, o.expected, o.decision, o.reason]
            if with_results:
                opt.append(o.result)
            opts.append(opt)
        print(json.dumps(opts))
        return

    # table header
    sep_line_len = 91
    if with_results:
        sep_line_len += 30
    print('=' * sep_line_len)
    print('{:^45}|{:^13}|{:^10}|{:^20}'.format('option name', 'desired val', 'decision', 'reason'), end='')
    if with_results:
        print('|   {}'.format('check result'), end='')
    print()
    print('=' * sep_line_len)

    # table contents
    for opt in checklist:
        opt.table_print(with_results)
        print()
        if debug_mode:
            print('-' * sep_line_len)
    print()


def perform_checks(checklist, parsed_options):
    for opt in checklist:
        if hasattr(opt, 'opts'):
            # prepare ComplexOptCheck
            for o in opt.opts:
                if hasattr(o, 'state'):
                    o.state = parsed_options.get(o.name, None)
        else:
            # prepare simple check
            if not hasattr(opt, 'state'):
                sys.exit('[!] ERROR: bad simple check {}'.format(vars(opt)))
            opt.state = parsed_options.get(opt.name, None)
        opt.check()


def check_config_file(checklist, fname, arch):
    with open(fname, 'r') as f:
        parsed_options = OrderedDict()
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        if not json_mode:
            print('[+] Checking "{}" against {} hardening preferences...'.format(fname, arch))
        for line in f.readlines():
            line = line.strip()
            option = None
            value = None

            if opt_is_on.match(line):
                option, value = line[7:].split('=', 1)
            elif opt_is_off.match(line):
                option, value = line[9:].split(' ', 1)
                if value != 'is not set':
                    sys.exit('[!] ERROR: bad disabled config option "{}"'.format(line))

            if option in parsed_options:
                sys.exit('[!] ERROR: config option "{}" exists multiple times'.format(line))

            if option is not None:
                parsed_options[option] = value

        perform_checks(checklist, parsed_options)

        if debug_mode:
            known_options = []
            for opt in checklist:
                if hasattr(opt, 'opts'):
                    for o in opt.opts:
                        if hasattr(o, 'name'):
                            known_options.append(o.name)
                else:
                    known_options.append(opt.name)
            for option, value in parsed_options.items():
                if option not in known_options:
                    print('DEBUG: dunno about option {} ({})'.format(option, value))

        print_checklist(checklist, True)

def main():
    global debug_mode
    global json_mode
    global kernel_version

    config_checklist = []

    parser = ArgumentParser(prog='kconfig-hardened-check',
                            description='Checks the hardening options in the Linux kernel config')
    parser.add_argument('-p', '--print', choices=supported_archs,
                        help='print hardening preferences for selected architecture')
    parser.add_argument('-c', '--config',
                        help='check the config_file against these preferences')
    parser.add_argument('--debug', action='store_true',
                        help='enable verbose debug mode')
    parser.add_argument('--json', action='store_true',
                        help='print results in JSON format')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    args = parser.parse_args()

    if args.debug:
        debug_mode = True
        print('[!] WARNING: debug mode is enabled')
    if args.json:
        json_mode = True
    if debug_mode and json_mode:
        sys.exit('[!] ERROR: options --debug and --json cannot be used simultaneously')

    if args.config:
        arch, msg = detect_arch(args.config)
        if not arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            print('[+] Detected architecture: {}'.format(arch))

        kernel_version, msg = detect_version(args.config)
        if not kernel_version:
            sys.exit('[!] ERROR: {}'.format(msg))
        elif not json_mode:
            print('[+] Detected kernel version: {}.{}'.format(kernel_version[0], kernel_version[1]))

        construct_checklist(config_checklist, arch)
        check_config_file(config_checklist, args.config, arch)
        error_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), config_checklist)))
        ok_count = len(list(filter(lambda opt: opt.result.startswith('OK'), config_checklist)))
        if not debug_mode and not json_mode:
            print('[+] config check is finished: \'OK\' - {} / \'FAIL\' - {}'.format(ok_count, error_count))
        sys.exit(0)

    if args.print:
        arch = args.print
        construct_checklist(config_checklist, arch)
        if not json_mode:
            print('[+] Printing kernel hardening preferences for {}...'.format(arch))
        print_checklist(config_checklist, False)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)

if __name__ == '__main__':
    main()
