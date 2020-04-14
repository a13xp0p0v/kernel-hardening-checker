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
    def __init__(self, name, expected, decision, reason):
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
            return True, self.result
        return False, self.result

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
            return True, self.result
        if kernel_version[0] < self.ver_expected[0]:
            self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return False, self.result
        if kernel_version[1] >= self.ver_expected[1]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return True, self.result
        self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
        return False, self.result

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
            return False, self.result
        self.result = 'OK: is present'
        return True, self.result

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
    def state(self):
        return self.opts[0].state

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
            ret, _ = opt.check()
            if ret:
                if i == 0 or not hasattr(opt, 'expected'):
                    self.result = opt.result
                else:
                    self.result = 'OK: CONFIG_{} "{}"'.format(opt.name, opt.expected)
                return True, self.result
        self.result = self.opts[0].result
        return False, self.result


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use case: AND(<suboption>, <main_option>)
    # Suboption is not checked if checking of the main_option is failed.

    def check(self):
        for i, opt in reversed(list(enumerate(self.opts))):
            ret, _ = opt.check()
            if i == 0:
                self.result = opt.result
                return ret, self.result
            if not ret:
                if hasattr(opt, 'expected'):
                    self.result = 'FAIL: CONFIG_{} is needed'.format(opt.name)
                else:
                    self.result = opt.result
                return False, self.result

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


def construct_checklist(checklist, arch):
    modules_not_set = OptCheck('MODULES',     'is not set', 'kspp', 'cut_attack_surface')
    devmem_not_set = OptCheck('DEVMEM',       'is not set', 'kspp', 'cut_attack_surface') # refers to LOCKDOWN

    checklist.append(OptCheck('BUG',                         'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('STRICT_KERNEL_RWX',        'y', 'defconfig', 'self_protection'), \
                        OptCheck('DEBUG_RODATA',             'y', 'defconfig', 'self_protection'))) # before v4.11
    checklist.append(OR(OptCheck('STACKPROTECTOR_STRONG',    'y', 'defconfig', 'self_protection'), \
                        OptCheck('CC_STACKPROTECTOR_STRONG', 'y', 'defconfig', 'self_protection')))
    checklist.append(OptCheck('SLUB_DEBUG',                  'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('STRICT_MODULE_RWX',        'y', 'defconfig', 'self_protection'), \
                        OptCheck('DEBUG_SET_MODULE_RONX',    'y', 'defconfig', 'self_protection'), \
                        modules_not_set)) # DEBUG_SET_MODULE_RONX was before v4.11
    checklist.append(OptCheck('GCC_PLUGINS',                 'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('REFCOUNT_FULL',            'y', 'defconfig', 'self_protection'), \
                        VerCheck((5, 5)))) # REFCOUNT_FULL is enabled by default since v5.5
    iommu_support_is_set = OptCheck('IOMMU_SUPPORT',         'y', 'defconfig', 'self_protection') # is needed for mitigating DMA attacks
    checklist.append(iommu_support_is_set)
    if arch in ('X86_64', 'X86_32'):
        checklist.append(OptCheck('MICROCODE',                   'y', 'defconfig', 'self_protection')) # is needed for mitigating CPU bugs
        checklist.append(OptCheck('RETPOLINE',                   'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('X86_SMAP',                    'y', 'defconfig', 'self_protection'))
        checklist.append(OR(OptCheck('X86_UMIP',                 'y', 'defconfig', 'self_protection'), \
                            OptCheck('X86_INTEL_UMIP',           'y', 'defconfig', 'self_protection')))
        checklist.append(OptCheck('SYN_COOKIES',                 'y', 'defconfig', 'self_protection')) # another reason?
    if arch == 'X86_64':
        checklist.append(OptCheck('PAGE_TABLE_ISOLATION',        'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('RANDOMIZE_MEMORY',            'y', 'defconfig', 'self_protection'))
        checklist.append(AND(OptCheck('INTEL_IOMMU',             'y', 'defconfig', 'self_protection'), \
                             iommu_support_is_set))
        checklist.append(AND(OptCheck('AMD_IOMMU',               'y', 'defconfig', 'self_protection'), \
                             iommu_support_is_set))
    if arch == 'ARM64':
        checklist.append(OptCheck('UNMAP_KERNEL_AT_EL0',         'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('HARDEN_EL2_VECTORS',          'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('RODATA_FULL_DEFAULT_ENABLED', 'y', 'defconfig', 'self_protection'))
    if arch in ('X86_64', 'ARM64'):
        checklist.append(OptCheck('VMAP_STACK',                  'y', 'defconfig', 'self_protection'))
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        checklist.append(OptCheck('RANDOMIZE_BASE',              'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('THREAD_INFO_IN_TASK',         'y', 'defconfig', 'self_protection'))
    if arch == 'ARM':
        checklist.append(OptCheck('CPU_SW_DOMAIN_PAN',           'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('STACKPROTECTOR_PER_TASK',     'y', 'defconfig', 'self_protection'))
    if arch in ('ARM64', 'ARM'):
        checklist.append(OptCheck('HARDEN_BRANCH_PREDICTOR',     'y', 'defconfig', 'self_protection'))

    checklist.append(OptCheck('BUG_ON_DATA_CORRUPTION',           'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_WX',                         'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SCHED_STACK_END_CHECK',            'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SLAB_FREELIST_HARDENED',           'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SLAB_FREELIST_RANDOM',             'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SHUFFLE_PAGE_ALLOCATOR',           'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('FORTIFY_SOURCE',                   'y', 'kspp', 'self_protection'))
    randstruct_is_set = OptCheck('GCC_PLUGIN_RANDSTRUCT',         'y', 'kspp', 'self_protection')
    checklist.append(randstruct_is_set)
    checklist.append(OptCheck('GCC_PLUGIN_LATENT_ENTROPY',        'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_LIST',                       'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_SG',                         'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_CREDENTIALS',                'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_NOTIFIERS',                  'y', 'kspp', 'self_protection'))
    hardened_usercopy_is_set = OptCheck('HARDENED_USERCOPY',      'y', 'kspp', 'self_protection')
    checklist.append(hardened_usercopy_is_set)
    checklist.append(AND(OptCheck('HARDENED_USERCOPY_FALLBACK',   'is not set', 'kspp', 'self_protection'), \
                         hardened_usercopy_is_set))
    checklist.append(OR(OptCheck('MODULE_SIG',                    'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OR(OptCheck('MODULE_SIG_ALL',                'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OR(OptCheck('MODULE_SIG_SHA512',             'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OR(OptCheck('MODULE_SIG_FORCE',              'y', 'kspp', 'self_protection'), \
                        modules_not_set)) # refers to LOCKDOWN
    checklist.append(OR(OptCheck('INIT_STACK_ALL',                'y', 'kspp', 'self_protection'), \
                      OptCheck('GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y', 'kspp', 'self_protection')))
    checklist.append(OptCheck('INIT_ON_ALLOC_DEFAULT_ON',         'y', 'kspp', 'self_protection'))
    checklist.append(OR(OptCheck('INIT_ON_FREE_DEFAULT_ON',       'y', 'kspp', 'self_protection'), \
                        OptCheck('PAGE_POISONING',                'y', 'kspp', 'self_protection'))) # before v5.3
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        stackleak_is_set = OptCheck('GCC_PLUGIN_STACKLEAK',       'y', 'kspp', 'self_protection')
        checklist.append(stackleak_is_set)
        checklist.append(AND(OptCheck('STACKLEAK_METRICS',         'is not set', 'clipos', 'self_protection'), \
                             stackleak_is_set))
        checklist.append(AND(OptCheck('STACKLEAK_RUNTIME_DISABLE', 'is not set', 'clipos', 'self_protection'), \
                             stackleak_is_set))
    if arch in ('X86_64', 'X86_32'):
        checklist.append(OptCheck('DEFAULT_MMAP_MIN_ADDR',            '65536', 'kspp', 'self_protection'))
    if arch == 'X86_32':
        checklist.append(OptCheck('PAGE_TABLE_ISOLATION',             'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('HIGHMEM64G',                       'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('X86_PAE',                          'y', 'kspp', 'self_protection'))
    if arch == 'ARM64':
        checklist.append(OptCheck('ARM64_SW_TTBR0_PAN',               'y', 'kspp', 'self_protection'))
    if arch in ('ARM64', 'ARM'):
        checklist.append(OptCheck('SYN_COOKIES',                      'y', 'kspp', 'self_protection')) # another reason?
        checklist.append(OptCheck('DEFAULT_MMAP_MIN_ADDR',            '32768', 'kspp', 'self_protection'))

    checklist.append(OptCheck('SECURITY_DMESG_RESTRICT',               'y', 'clipos', 'self_protection'))
    checklist.append(OptCheck('DEBUG_VIRTUAL',                         'y', 'clipos', 'self_protection'))
    checklist.append(OptCheck('STATIC_USERMODEHELPER',                 'y', 'clipos', 'self_protection')) # needs userspace support (systemd)
    checklist.append(OptCheck('SLAB_MERGE_DEFAULT',                    'is not set', 'clipos', 'self_protection')) # slab_nomerge
    checklist.append(AND(OptCheck('GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set', 'clipos', 'self_protection'), \
                         randstruct_is_set))
    checklist.append(OptCheck('RANDOM_TRUST_BOOTLOADER',               'is not set', 'clipos', 'self_protection'))
    checklist.append(OptCheck('RANDOM_TRUST_CPU',                      'is not set', 'clipos', 'self_protection'))
    if arch in ('X86_64', 'X86_32'):
        checklist.append(AND(OptCheck('INTEL_IOMMU_SVM',                   'y', 'clipos', 'self_protection'), \
                             iommu_support_is_set))
        checklist.append(AND(OptCheck('INTEL_IOMMU_DEFAULT_ON',            'y', 'clipos', 'self_protection'), \
                             iommu_support_is_set))
    if arch == 'X86_32':
        checklist.append(AND(OptCheck('INTEL_IOMMU',                       'y', 'clipos', 'self_protection'), \
                             iommu_support_is_set))

    checklist.append(OptCheck('SLUB_DEBUG_ON',                      'y', 'my', 'self_protection'))
    checklist.append(OptCheck('RESET_ATTACK_MITIGATION',            'y', 'my', 'self_protection')) # needs userspace support (systemd)
    if arch == 'X86_64':
        checklist.append(AND(OptCheck('AMD_IOMMU_V2',                   'y', 'my', 'self_protection'), \
                             iommu_support_is_set))

    if arch in ('X86_64', 'ARM64', 'X86_32'):
        checklist.append(OptCheck('SECURITY',                               'y', 'defconfig', 'security_policy')) # and choose your favourite LSM
    if arch == 'ARM':
        checklist.append(OptCheck('SECURITY',                               'y', 'kspp', 'security_policy')) # and choose your favourite LSM
    checklist.append(OptCheck('SECURITY_YAMA',                          'y', 'kspp', 'security_policy'))
    checklist.append(OR(OptCheck('SECURITY_WRITABLE_HOOKS',             'is not set', 'my', 'security_policy'), \
                        OptCheck('SECURITY_SELINUX_DISABLE',            'is not set', 'kspp', 'security_policy')))
    checklist.append(OptCheck('SECURITY_LOCKDOWN_LSM',                  'y', 'clipos', 'security_policy'))
    checklist.append(OptCheck('SECURITY_LOCKDOWN_LSM_EARLY',            'y', 'clipos', 'security_policy'))
    checklist.append(OptCheck('LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y', 'clipos', 'security_policy'))
    loadpin_is_set = OptCheck('SECURITY_LOADPIN',                       'y', 'my', 'security_policy') # needs userspace support
    checklist.append(loadpin_is_set)
    checklist.append(AND(OptCheck('SECURITY_LOADPIN_ENFORCE',           'y', 'my', 'security_policy'), \
                         loadpin_is_set))
    checklist.append(OptCheck('SECURITY_SAFESETID',                     'y', 'my', 'security_policy'))

    checklist.append(OptCheck('SECCOMP',              'y', 'defconfig', 'cut_attack_surface'))
    checklist.append(OptCheck('SECCOMP_FILTER',       'y', 'defconfig', 'cut_attack_surface'))
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        checklist.append(OR(OptCheck('STRICT_DEVMEM',     'y', 'defconfig', 'cut_attack_surface'), \
                            devmem_not_set)) # refers to LOCKDOWN

    checklist.append(modules_not_set)
    checklist.append(devmem_not_set)
    checklist.append(OR(OptCheck('IO_STRICT_DEVMEM',  'y', 'kspp', 'cut_attack_surface'), \
                        devmem_not_set)) # refers to LOCKDOWN
    if arch == 'ARM':
        checklist.append(OR(OptCheck('STRICT_DEVMEM',     'y', 'kspp', 'cut_attack_surface'), \
                            devmem_not_set)) # refers to LOCKDOWN
    if arch == 'X86_64':
        checklist.append(OptCheck('LEGACY_VSYSCALL_NONE', 'y', 'kspp', 'cut_attack_surface')) # 'vsyscall=none'
    checklist.append(OptCheck('ACPI_CUSTOM_METHOD',   'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('COMPAT_BRK',           'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('DEVKMEM',              'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('COMPAT_VDSO',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('BINFMT_MISC',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('INET_DIAG',            'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('KEXEC',                'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('PROC_KCORE',           'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('LEGACY_PTYS',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('HIBERNATION',          'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('IA32_EMULATION',       'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('X86_X32',              'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('MODIFY_LDT_SYSCALL',   'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('OABI_COMPAT',          'is not set', 'kspp', 'cut_attack_surface'))

    checklist.append(OptCheck('X86_PTDUMP',              'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('ZSMALLOC_STAT',           'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('PAGE_OWNER',              'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('DEBUG_KMEMLEAK',          'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('BINFMT_AOUT',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('KPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('UPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('GENERIC_TRACER',          'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('PROC_VMCORE',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('PROC_PAGE_MONITOR',       'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('USELIB',                  'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('CHECKPOINT_RESTORE',      'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('USERFAULTFD',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('HWPOISON_INJECT',         'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('MEM_SOFT_DIRTY',          'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('DEVPORT',                 'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('DEBUG_FS',                'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('NOTIFIER_ERROR_INJECTION','is not set', 'grsecurity', 'cut_attack_surface'))

    checklist.append(OptCheck('DRM_LEGACY',     'is not set', 'maintainer', 'cut_attack_surface'))
    checklist.append(OptCheck('FB',             'is not set', 'maintainer', 'cut_attack_surface'))
    checklist.append(OptCheck('VT',             'is not set', 'maintainer', 'cut_attack_surface'))

    checklist.append(OptCheck('ACPI_TABLE_UPGRADE',   'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('X86_IOPL_IOPERM',      'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('EFI_TEST',             'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('BPF_SYSCALL',          'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('MMIOTRACE_TEST',       'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCKDOWN

    if arch in ('X86_64', 'X86_32'):
        checklist.append(OptCheck('X86_INTEL_TSX_MODE_OFF',   'y', 'clipos', 'cut_attack_surface')) # tsx=off
    checklist.append(OptCheck('STAGING',                  'is not set', 'clipos', 'cut_attack_surface'))
    checklist.append(OptCheck('KSM',                      'is not set', 'clipos', 'cut_attack_surface')) # to prevent FLUSH+RELOAD attack
#   checklist.append(OptCheck('IKCONFIG',                 'is not set', 'clipos', 'cut_attack_surface')) # no, this info is needed for this check :)
    checklist.append(OptCheck('KALLSYMS',                 'is not set', 'clipos', 'cut_attack_surface'))
    checklist.append(OptCheck('X86_VSYSCALL_EMULATION',   'is not set', 'clipos', 'cut_attack_surface'))
    checklist.append(OptCheck('MAGIC_SYSRQ',              'is not set', 'clipos', 'cut_attack_surface'))
    checklist.append(OptCheck('KEXEC_FILE',               'is not set', 'clipos', 'cut_attack_surface')) # refers to LOCKDOWN (permissive)
    checklist.append(OptCheck('USER_NS',                  'is not set', 'clipos', 'cut_attack_surface')) # user.max_user_namespaces=0
    checklist.append(OptCheck('X86_MSR',                  'is not set', 'clipos', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('X86_CPUID',                'is not set', 'clipos', 'cut_attack_surface'))
    checklist.append(AND(OptCheck('LDISC_AUTOLOAD',           'is not set', 'clipos', 'cut_attack_surface'), \
                         PresenceCheck('LDISC_AUTOLOAD')))

    checklist.append(OptCheck('AIO',                  'is not set', 'grapheneos', 'cut_attack_surface'))

    checklist.append(OptCheck('MMIOTRACE',            'is not set', 'my', 'cut_attack_surface')) # refers to LOCKDOWN (permissive)
    checklist.append(OptCheck('LIVEPATCH',            'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('IP_DCCP',              'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('IP_SCTP',              'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('FTRACE',               'is not set', 'my', 'cut_attack_surface')) # refers to LOCKDOWN
    checklist.append(OptCheck('BPF_JIT',              'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('VIDEO_VIVID',          'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('INPUT_EVBUG',          'is not set', 'my', 'cut_attack_surface')) # Can be used as a keylogger

    checklist.append(OptCheck('INTEGRITY',       'y', 'defconfig', 'userspace_hardening'))
    if arch == 'ARM64':
        checklist.append(OptCheck('ARM64_PTR_AUTH',       'y', 'defconfig', 'userspace_hardening'))
    if arch in ('ARM', 'X86_32'):
        checklist.append(OptCheck('VMSPLIT_3G',           'y', 'defconfig', 'userspace_hardening'))
    if arch in ('X86_64', 'ARM64'):
        checklist.append(OptCheck('ARCH_MMAP_RND_BITS',   '32', 'clipos', 'userspace_hardening'))
    if arch in ('X86_32', 'ARM'):
        checklist.append(OptCheck('ARCH_MMAP_RND_BITS',   '16', 'my', 'userspace_hardening'))

#   checklist.append(OptCheck('LKDTM',    'm', 'my', 'feature_test'))


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
    main2(args)
    #parser.print_help()
    sys.exit(0)

def main2(args):
    global debug_mode
    global json_mode
    global kernel_version

    config_checklist = []

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
        #sys.exit(0)
        return

    if args.print:
        arch = args.print
        construct_checklist(config_checklist, arch)
        if not json_mode:
            print('[+] Printing kernel hardening preferences for {}...'.format(arch))
        print_checklist(config_checklist, False)
        sys.exit(0)


if __name__ == '__main__':
    main()
