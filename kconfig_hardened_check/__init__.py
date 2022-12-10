#!/usr/bin/python3

#
# This tool helps me to check Linux kernel options against
# my security hardening preferences for X86_64, ARM64, X86_32, and ARM.
# Let the computers do their job!
#
# Author: Alexander Popov <alex.popov@linux.com>
#
# Please don't cry if my Python code looks like C.
#
#
# N.B Hardening command line parameters:
#    iommu=force (does it help against DMA attacks?)
#
#    Mitigations of CPU vulnerabilities:
#       Аrch-independent:
#       X86:
#           l1d_flush=on (a part of the l1tf option)
#           tsx=off
#       ARM64:
#           kpti=on
#
#           arm64.nomte
#
#    Hardware tag-based KASAN with arm64 Memory Tagging Extension (MTE):
#           kasan=on
#           kasan.stacktrace=off
#           kasan.fault=panic
#
# N.B. Hardening sysctls:
#    kernel.kptr_restrict=2 (or 1?)
#    kernel.dmesg_restrict=1 (also see the kconfig option)
#    kernel.perf_event_paranoid=3
#    kernel.kexec_load_disabled=1
#    kernel.yama.ptrace_scope=3
#    user.max_user_namespaces=0
#    what about bpf_jit_enable?
#    kernel.unprivileged_bpf_disabled=1
#    net.core.bpf_jit_harden=2
#    vm.unprivileged_userfaultfd=0
#        (at first, it disabled unprivileged userfaultfd,
#         and since v5.11 it enables unprivileged userfaultfd for user-mode only)
#    vm.mmap_min_addr has a good value
#    dev.tty.ldisc_autoload=0
#    fs.protected_symlinks=1
#    fs.protected_hardlinks=1
#    fs.protected_fifos=2
#    fs.protected_regular=2
#    fs.suid_dumpable=0
#    kernel.modules_disabled=1
#    kernel.randomize_va_space = 2


# pylint: disable=missing-module-docstring,missing-class-docstring,missing-function-docstring
# pylint: disable=line-too-long,invalid-name,too-many-branches,too-many-statements


import sys
from argparse import ArgumentParser
from collections import OrderedDict
import re
import json
from .__about__ import __version__

SIMPLE_OPTION_TYPES = ('kconfig', 'version', 'cmdline')

class OptCheck:
    def __init__(self, reason, decision, name, expected):
        assert(name and name == name.strip() and len(name.split()) == 1), \
               'invalid name "{}" for {}'.format(name, self.__class__.__name__)
        self.name = name

        assert(decision and decision == decision.strip() and len(decision.split()) == 1), \
               'invalid decision "{}" for "{}" check'.format(decision, name)
        self.decision = decision

        assert(reason and reason == reason.strip() and len(reason.split()) == 1), \
               'invalid reason "{}" for "{}" check'.format(reason, name)
        self.reason = reason

        assert(expected and expected == expected.strip()), \
               'invalid expected value "{}" for "{}" check (1)'.format(expected, name)
        val_len = len(expected.split())
        if val_len == 3:
            assert(expected == 'is not set' or expected == 'is not off'), \
                   'invalid expected value "{}" for "{}" check (2)'.format(expected, name)
        elif val_len == 2:
            assert(expected == 'is present'), \
                   'invalid expected value "{}" for "{}" check (3)'.format(expected, name)
        else:
            assert(val_len == 1), \
                   'invalid expected value "{}" for "{}" check (4)'.format(expected, name)
        self.expected = expected

        self.state = None
        self.result = None

    @property
    def type(self):
        return None

    def check(self):
        # handle the 'is present' check
        if self.expected == 'is present':
            if self.state is None:
                self.result = 'FAIL: is not present'
            else:
                self.result = 'OK: is present'
            return

        # handle the 'is not off' option check
        if self.expected == 'is not off':
            if self.state == 'off':
                self.result = 'FAIL: is off'
            elif self.state is None:
                self.result = 'FAIL: is off, not found'
            else:
                self.result = 'OK: is not off, "' + self.state + '"'
            return

        # handle the option value check
        if self.expected == self.state:
            self.result = 'OK'
        elif self.state is None:
            if self.expected == 'is not set':
                self.result = 'OK: is not found'
            else:
                self.result = 'FAIL: is not found'
        else:
            self.result = 'FAIL: "' + self.state + '"'

    def table_print(self, _mode, with_results):
        print('{:<40}|{:^7}|{:^12}|{:^10}|{:^18}'.format(self.name, self.type, self.expected, self.decision, self.reason), end='')
        if with_results:
            print('| {}'.format(self.result), end='')

    def json_dump(self, with_results):
        dump = [self.name, self.type, self.expected, self.decision, self.reason]
        if with_results:
            dump.append(self.result)
        return dump


class KconfigCheck(OptCheck):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = 'CONFIG_' + self.name

    @property
    def type(self):
        return 'kconfig'


class CmdlineCheck(OptCheck):
    @property
    def type(self):
        return 'cmdline'


class VersionCheck:
    def __init__(self, ver_expected):
        assert(ver_expected and isinstance(ver_expected, tuple) and len(ver_expected) == 2), \
               'invalid version "{}" for VersionCheck'.format(ver_expected)
        self.ver_expected = ver_expected
        self.ver = ()
        self.result = None

    @property
    def type(self):
        return 'version'

    def check(self):
        if self.ver[0] > self.ver_expected[0]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        if self.ver[0] < self.ver_expected[0]:
            self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        if self.ver[1] >= self.ver_expected[1]:
            self.result = 'OK: version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
            return
        self.result = 'FAIL: version < ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])

    def table_print(self, _mode, with_results):
        ver_req = 'kernel version >= ' + str(self.ver_expected[0]) + '.' + str(self.ver_expected[1])
        print('{:<91}'.format(ver_req), end='')
        if with_results:
            print('| {}'.format(self.result), end='')


class ComplexOptCheck:
    def __init__(self, *opts):
        self.opts = opts
        assert(self.opts), \
               'empty {} check'.format(self.__class__.__name__)
        assert(len(self.opts) != 1), \
                'useless {} check: {}'.format(self.__class__.__name__, opts)
        assert(isinstance(opts[0], (KconfigCheck, CmdlineCheck))), \
               'invalid {} check: {}'.format(self.__class__.__name__, opts)
        self.result = None

    @property
    def type(self):
        return 'complex'

    @property
    def name(self):
        return self.opts[0].name

    @property
    def expected(self):
        return self.opts[0].expected

    def table_print(self, mode, with_results):
        if mode == 'verbose':
            print('    {:87}'.format('<<< ' + self.__class__.__name__ + ' >>>'), end='')
            if with_results:
                print('| {}'.format(self.result), end='')
            for o in self.opts:
                print()
                o.table_print(mode, with_results)
        else:
            o = self.opts[0]
            o.table_print(mode, False)
            if with_results:
                print('| {}'.format(self.result), end='')

    def json_dump(self, with_results):
        dump = self.opts[0].json_dump(False)
        if with_results:
            dump.append(self.result)
        return dump


class OR(ComplexOptCheck):
    # self.opts[0] is the option that this OR-check is about.
    # Use cases:
    #     OR(<X_is_hardened>, <X_is_disabled>)
    #     OR(<X_is_hardened>, <old_X_is_hardened>)
    def check(self):
        for i, opt in enumerate(self.opts):
            opt.check()
            if opt.result.startswith('OK'):
                self.result = opt.result
                # Add more info for additional checks:
                if i != 0:
                    if opt.result == 'OK':
                        self.result = 'OK: {} is "{}"'.format(opt.name, opt.expected)
                    elif opt.result == 'OK: is not found':
                        self.result = 'OK: {} is not found'.format(opt.name)
                    elif opt.result == 'OK: is present':
                        self.result = 'OK: {} is present'.format(opt.name)
                    elif opt.result.startswith('OK: is not off'):
                        self.result = 'OK: {} is not off'.format(opt.name)
                    else:
                        # VersionCheck provides enough info
                        assert(opt.result.startswith('OK: version')), \
                               'unexpected OK description "{}"'.format(opt.result)
                return
        self.result = self.opts[0].result


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use cases:
    #     AND(<suboption>, <main_option>)
    #       Suboption is not checked if checking of the main_option is failed.
    #     AND(<X_is_disabled>, <old_X_is_disabled>)
    def check(self):
        for i, opt in reversed(list(enumerate(self.opts))):
            opt.check()
            if i == 0:
                self.result = opt.result
                return
            if not opt.result.startswith('OK'):
                # This FAIL is caused by additional checks,
                # and not by the main option that this AND-check is about.
                # Describe the reason of the FAIL.
                if opt.result.startswith('FAIL: \"') or opt.result == 'FAIL: is not found':
                    self.result = 'FAIL: {} is not "{}"'.format(opt.name, opt.expected)
                elif opt.result == 'FAIL: is not present':
                    self.result = 'FAIL: {} is not present'.format(opt.name)
                elif opt.result == 'FAIL: is off':
                    self.result = 'FAIL: {} is off'.format(opt.name)
                elif opt.result == 'FAIL: is off, not found':
                    self.result = 'FAIL: {} is off, not found'.format(opt.name)
                else:
                    # VersionCheck provides enough info
                    self.result = opt.result
                    assert(opt.result.startswith('FAIL: version')), \
                           'unexpected FAIL description "{}"'.format(opt.result)
                return


def detect_arch(fname, archs):
    with open(fname, 'r') as f:
        arch_pattern = re.compile("CONFIG_[a-zA-Z0-9_]*=y")
        arch = None
        for line in f.readlines():
            if arch_pattern.match(line):
                option, _ = line[7:].split('=', 1)
                if option in archs:
                    if not arch:
                        arch = option
                    else:
                        return None, 'more than one supported architecture is detected'
        if not arch:
            return None, 'failed to detect architecture'
        return arch, 'OK'


def detect_kernel_version(fname):
    with open(fname, 'r') as f:
        ver_pattern = re.compile("# Linux/.* Kernel Configuration")
        for line in f.readlines():
            if ver_pattern.match(line):
                line = line.strip()
                parts = line.split()
                ver_str = parts[2]
                ver_numbers = ver_str.split('.')
                if len(ver_numbers) < 3 or not ver_numbers[0].isdigit() or not ver_numbers[1].isdigit():
                    msg = 'failed to parse the version "' + ver_str + '"'
                    return None, msg
                return (int(ver_numbers[0]), int(ver_numbers[1])), None
        return None, 'no kernel version detected'


def detect_compiler(fname):
    gcc_version = None
    clang_version = None
    with open(fname, 'r') as f:
        gcc_version_pattern = re.compile("CONFIG_GCC_VERSION=[0-9]*")
        clang_version_pattern = re.compile("CONFIG_CLANG_VERSION=[0-9]*")
        for line in f.readlines():
            if gcc_version_pattern.match(line):
                gcc_version = line[19:-1]
            if clang_version_pattern.match(line):
                clang_version = line[21:-1]
    if not gcc_version or not clang_version:
        return None, 'no CONFIG_GCC_VERSION or CONFIG_CLANG_VERSION'
    if gcc_version == '0' and clang_version != '0':
        return 'CLANG ' + clang_version, 'OK'
    if gcc_version != '0' and clang_version == '0':
        return 'GCC ' + gcc_version, 'OK'
    sys.exit('[!] ERROR: invalid GCC_VERSION and CLANG_VERSION: {} {}'.format(gcc_version, clang_version))


def add_kconfig_checks(l, arch):
    # Calling the KconfigCheck class constructor:
    #     KconfigCheck(reason, decision, name, expected)
    #
    # [!] Don't add CmdlineChecks in add_kconfig_checks() to avoid wrong results
    #     when the tool doesn't check the cmdline.

    efi_not_set = KconfigCheck('-', '-', 'EFI', 'is not set')
    cc_is_gcc = KconfigCheck('-', '-', 'CC_IS_GCC', 'y') # exists since v4.18
    cc_is_clang = KconfigCheck('-', '-', 'CC_IS_CLANG', 'y') # exists since v4.18

    modules_not_set = KconfigCheck('cut_attack_surface', 'kspp', 'MODULES', 'is not set')
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
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y')]
    if arch in ('X86_64', 'ARM64'):
        l += [KconfigCheck('self_protection', 'defconfig', 'VMAP_STACK', 'y')]
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE_INTEL', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'X86_MCE_AMD', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'MICROCODE', 'y')] # is needed for mitigating CPU bugs
        l += [KconfigCheck('self_protection', 'defconfig', 'RETPOLINE', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'SYN_COOKIES', 'y')] # another reason?
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_SMAP', 'y'),
                 VersionCheck((5, 19)))] # X86_SMAP is enabled by default since v5.19
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'X86_UMIP', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'X86_INTEL_UMIP', 'y'))]
    if arch in ('ARM64', 'ARM'):
        l += [KconfigCheck('self_protection', 'defconfig', 'STACKPROTECTOR_PER_TASK', 'y')]
    if arch == 'X86_64':
        l += [KconfigCheck('self_protection', 'defconfig', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [KconfigCheck('self_protection', 'defconfig', 'RANDOMIZE_MEMORY', 'y')]
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

    # 'self_protection', 'kspp'
    l += [KconfigCheck('self_protection', 'kspp', 'BUG_ON_DATA_CORRUPTION', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_WX', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SCHED_STACK_END_CHECK', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_HARDENED', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SLAB_FREELIST_RANDOM', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'SHUFFLE_PAGE_ALLOCATOR', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'FORTIFY_SOURCE', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_LIST', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_VIRTUAL', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_SG', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_CREDENTIALS', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'DEBUG_NOTIFIERS', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'KFENCE', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'WERROR', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set')] # true if IOMMU_DEFAULT_DMA_STRICT is set
    l += [KconfigCheck('self_protection', 'kspp', 'ZERO_CALL_USED_REGS', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'HW_RANDOM_TPM', 'y')]
    l += [KconfigCheck('self_protection', 'kspp', 'STATIC_USERMODEHELPER', 'y')] # needs userspace support
    l += [KconfigCheck('self_protection', 'kspp', 'SCHED_CORE', 'y')]
    randstruct_is_set = OR(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_FULL', 'y'),
                           KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT', 'y'))
    l += [randstruct_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'RANDSTRUCT_PERFORMANCE', 'is not set'),
              KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set'),
              randstruct_is_set)]
    hardened_usercopy_is_set = KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y')
    l += [hardened_usercopy_is_set]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'),
              hardened_usercopy_is_set)]
    l += [AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_PAGESPAN', 'is not set'),
              hardened_usercopy_is_set)]
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
    l += [OR(KconfigCheck('self_protection', 'kspp', 'INIT_STACK_ALL_ZERO', 'y'),
             KconfigCheck('self_protection', 'kspp', 'GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y'))]
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
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [AND(KconfigCheck('self_protection', 'kspp', 'UBSAN_SANITIZE_ALL', 'y'),
                  ubsan_bounds_is_set)] # ARCH_HAS_UBSAN_SANITIZE_ALL is not enabled for ARM
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
        cfi_clang_is_set = KconfigCheck('self_protection', 'kspp', 'CFI_CLANG', 'y')
        l += [cfi_clang_is_set]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'CFI_PERMISSIVE', 'is not set'),
                  cfi_clang_is_set)]
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536')]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU_DEFAULT_ON', 'y'),
                  iommu_support_is_set)]
    if arch in ('ARM64', 'ARM'):
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
        l += [KconfigCheck('self_protection', 'kspp', 'KASAN_HW_TAGS', 'y')]
    if arch == 'X86_32':
        l += [KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_ISOLATION', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'HIGHMEM64G', 'y')]
        l += [KconfigCheck('self_protection', 'kspp', 'X86_PAE', 'y')]
        l += [AND(KconfigCheck('self_protection', 'kspp', 'INTEL_IOMMU', 'y'),
                  iommu_support_is_set)]

    # 'self_protection', 'clipos'
    l += [KconfigCheck('self_protection', 'clipos', 'SLAB_MERGE_DEFAULT', 'is not set')]

    # 'security_policy'
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [KconfigCheck('security_policy', 'defconfig', 'SECURITY', 'y')] # and choose your favourite LSM
    if arch == 'ARM':
        l += [KconfigCheck('security_policy', 'kspp', 'SECURITY', 'y')] # and choose your favourite LSM
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_YAMA', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LANDLOCK', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DISABLE', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_BOOTPARAM', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_SELINUX_DEVELOP', 'is not set')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LOCKDOWN_LSM', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_LOCKDOWN_LSM_EARLY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'y')]
    l += [KconfigCheck('security_policy', 'kspp', 'SECURITY_WRITABLE_HOOKS', 'is not set')] # refers to SECURITY_SELINUX_DISABLE

    # 'cut_attack_surface', 'defconfig'
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'defconfig', 'SECCOMP_FILTER', 'y')]
    l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'BPF_UNPRIV_DEFAULT_OFF', 'y'),
             bpf_syscall_not_set)] # see unprivileged_bpf_disabled
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OR(KconfigCheck('cut_attack_surface', 'defconfig', 'STRICT_DEVMEM', 'y'),
                 devmem_not_set)] # refers to LOCKDOWN

    # 'cut_attack_surface', 'kspp'
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'SECURITY_DMESG_RESTRICT', 'y')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'ACPI_CUSTOM_METHOD', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_BRK', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'DEVKMEM', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'BINFMT_MISC', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'INET_DIAG', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'KEXEC', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'PROC_KCORE', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_PTYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'HIBERNATION', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_X32', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'MODIFY_LDT_SYSCALL', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'OABI_COMPAT', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'X86_MSR', 'is not set')] # refers to LOCKDOWN
    l += [modules_not_set]
    l += [devmem_not_set]
    l += [OR(KconfigCheck('cut_attack_surface', 'kspp', 'IO_STRICT_DEVMEM', 'y'),
             devmem_not_set)] # refers to LOCKDOWN
    l += [AND(KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is not set'),
              KconfigCheck('cut_attack_surface', 'kspp', 'LDISC_AUTOLOAD', 'is present'))]
    if arch == 'X86_64':
        l += [KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y')] # 'vsyscall=none'
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

    # 'cut_attack_surface', 'grapheneos'
    l += [KconfigCheck('cut_attack_surface', 'grapheneos', 'AIO', 'is not set')]

    # 'cut_attack_surface', 'clipos'
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'STAGING', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KSM', 'is not set')] # to prevent FLUSH+RELOAD attack
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KALLSYMS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_VSYSCALL_EMULATION', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'KEXEC_FILE', 'is not set')] # refers to LOCKDOWN (permissive)
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'USER_NS', 'is not set')] # user.max_user_namespaces=0
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_CPUID', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_IOPL_IOPERM', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'ACPI_TABLE_UPGRADE', 'is not set')] # refers to LOCKDOWN
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'EFI_CUSTOM_SSDT_OVERLAYS', 'is not set')]
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'COREDUMP', 'is not set')] # cut userspace attack surface
#   l += [KconfigCheck('cut_attack_surface', 'clipos', 'IKCONFIG', 'is not set')] # no, IKCONFIG is needed for this check :)
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('cut_attack_surface', 'clipos', 'X86_INTEL_TSX_MODE_OFF', 'y')] # tsx=off

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
    l += [OR(KconfigCheck('cut_attack_surface', 'my', 'TRIM_UNUSED_KSYMS', 'y'),
             modules_not_set)]

    # 'harden_userspace'
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [KconfigCheck('harden_userspace', 'defconfig', 'INTEGRITY', 'y')]
    if arch == 'ARM':
        l += [KconfigCheck('harden_userspace', 'my', 'INTEGRITY', 'y')]
    if arch == 'ARM64':
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_PTR_AUTH', 'y')]
        l += [KconfigCheck('harden_userspace', 'defconfig', 'ARM64_BTI', 'y')]
    if arch in ('ARM', 'X86_32'):
        l += [KconfigCheck('harden_userspace', 'defconfig', 'VMSPLIT_3G', 'y')]
    if arch in ('X86_64', 'ARM64'):
        l += [KconfigCheck('harden_userspace', 'clipos', 'ARCH_MMAP_RND_BITS', '32')]
    if arch in ('X86_32', 'ARM'):
        l += [KconfigCheck('harden_userspace', 'my', 'ARCH_MMAP_RND_BITS', '16')]


def add_cmdline_checks(l, arch):
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
    l += [CmdlineCheck('self_protection', 'defconfig', 'nospec_store_bypass_disable', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nobti', 'is not set')]
    l += [CmdlineCheck('self_protection', 'defconfig', 'arm64.nopauth', 'is not set')]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'mitigations', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'spectre_v2', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spectre_v2_user', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'spectre_v2_user', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'spec_store_bypass_disable', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'spec_store_bypass_disable', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'l1tf', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'l1tf', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mds', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'mds', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'tsx_async_abort', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'tsx_async_abort', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'srbds', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'srbds', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'mmio_stale_data', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'mmio_stale_data', 'is not set'))]
    l += [OR(CmdlineCheck('self_protection', 'defconfig', 'retbleed', 'is not off'),
             CmdlineCheck('self_protection', 'defconfig', 'retbleed', 'is not set'))]
    if arch == 'ARM64':
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'ssbd', 'kernel'),
                 CmdlineCheck('self_protection', 'my', 'ssbd', 'force-on'),
                 CmdlineCheck('self_protection', 'defconfig', 'ssbd', 'is not set'))]
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', 'full'),
                 AND(KconfigCheck('self_protection', 'defconfig', 'RODATA_FULL_DEFAULT_ENABLED', 'y'),
                     CmdlineCheck('self_protection', 'defconfig', 'rodata', 'is not set')))]
    else:
        l += [OR(CmdlineCheck('self_protection', 'defconfig', 'rodata', '1'),
                 CmdlineCheck('self_protection', 'defconfig', 'rodata', 'is not set'))]

    # 'self_protection', 'kspp'
    l += [CmdlineCheck('self_protection', 'kspp', 'nosmt', 'is present')]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_alloc', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_ALLOC_DEFAULT_ON', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'init_on_alloc', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'init_on_free', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'INIT_ON_FREE_DEFAULT_ON', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'init_on_free', 'is not set')),
             AND(CmdlineCheck('self_protection', 'kspp', 'page_poison', '1'),
                 KconfigCheck('self_protection', 'kspp', 'PAGE_POISONING_ZERO', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'slub_debug', 'P')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'slab_nomerge', 'is present'),
             AND(KconfigCheck('self_protection', 'clipos', 'SLAB_MERGE_DEFAULT', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slab_merge', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'iommu.strict', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_DMA_STRICT', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'iommu.strict', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'iommu.passthrough', '0'),
             AND(KconfigCheck('self_protection', 'kspp', 'IOMMU_DEFAULT_PASSTHROUGH', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'iommu.passthrough', 'is not set')))]
    # The cmdline checks compatible with the kconfig recommendations of the KSPP project...
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'hardened_usercopy', '1'),
             AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY', 'y'),
                 CmdlineCheck('self_protection', 'kspp', 'hardened_usercopy', 'is not set')))]
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'slab_common.usercopy_fallback', '0'),
             AND(KconfigCheck('self_protection', 'kspp', 'HARDENED_USERCOPY_FALLBACK', 'is not set'),
                 CmdlineCheck('self_protection', 'kspp', 'slab_common.usercopy_fallback', 'is not set')))]
    # ... the end
    if arch in ('X86_64', 'ARM64', 'X86_32'):
        l += [OR(CmdlineCheck('self_protection', 'kspp', 'randomize_kstack_offset', '1'),
                 AND(KconfigCheck('self_protection', 'kspp', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT', 'y'),
                     CmdlineCheck('self_protection', 'kspp', 'randomize_kstack_offset', 'is not set')))]
    if arch in ('X86_64', 'X86_32'):
        l += [AND(CmdlineCheck('self_protection', 'kspp', 'pti', 'on'),
                  CmdlineCheck('self_protection', 'defconfig', 'nopti', 'is not set'))]

    # 'self_protection', 'clipos'
    l += [CmdlineCheck('self_protection', 'clipos', 'page_alloc.shuffle', '1')]

    # 'cut_attack_surface', 'kspp'
    if arch == 'X86_64':
        l += [OR(CmdlineCheck('cut_attack_surface', 'kspp', 'vsyscall', 'none'),
                 AND(KconfigCheck('cut_attack_surface', 'kspp', 'LEGACY_VSYSCALL_NONE', 'y'),
                     CmdlineCheck('cut_attack_surface', 'kspp', 'vsyscall', 'is not set')))]

    # 'cut_attack_surface', 'grsec'
    # The cmdline checks compatible with the kconfig options disabled by grsecurity...
    l += [OR(CmdlineCheck('cut_attack_surface', 'grsec', 'debugfs', 'off'),
             KconfigCheck('cut_attack_surface', 'grsec', 'DEBUG_FS', 'is not set'))] # ... the end

    # 'cut_attack_surface', 'my'
    l += [CmdlineCheck('cut_attack_surface', 'my', 'sysrq_always_enabled', 'is not set')]

def print_unknown_options(checklist, parsed_options):
    known_options = []

    for o1 in checklist:
        if o1.type != 'complex':
            known_options.append(o1.name)
            continue
        for o2 in o1.opts:
            if o2.type != 'complex':
                if hasattr(o2, 'name'):
                    known_options.append(o2.name)
                continue
            for o3 in o2.opts:
                assert(o3.type != 'complex'), \
                       'unexpected ComplexOptCheck inside {}'.format(o2.name)
                if hasattr(o3, 'name'):
                    known_options.append(o3.name)

    for option, value in parsed_options.items():
        if option not in known_options:
            print('[?] No check for option {} ({})'.format(option, value))


def print_checklist(mode, checklist, with_results):
    if mode == 'json':
        output = []
        for o in checklist:
            output.append(o.json_dump(with_results))
        print(json.dumps(output))
        return

    # table header
    sep_line_len = 91
    if with_results:
        sep_line_len += 30
    print('=' * sep_line_len)
    print('{:^40}|{:^7}|{:^12}|{:^10}|{:^18}'.format('option name', 'type', 'desired val', 'decision', 'reason'), end='')
    if with_results:
        print('| {}'.format('check result'), end='')
    print()
    print('=' * sep_line_len)

    # table contents
    for opt in checklist:
        if with_results:
            if mode == 'show_ok':
                if not opt.result.startswith('OK'):
                    continue
            if mode == 'show_fail':
                if not opt.result.startswith('FAIL'):
                    continue
        opt.table_print(mode, with_results)
        print()
        if mode == 'verbose':
            print('-' * sep_line_len)
    print()

    # final score
    if with_results:
        fail_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), checklist)))
        fail_suppressed = ''
        ok_count = len(list(filter(lambda opt: opt.result.startswith('OK'), checklist)))
        ok_suppressed = ''
        if mode == 'show_ok':
            fail_suppressed = ' (suppressed in output)'
        if mode == 'show_fail':
            ok_suppressed = ' (suppressed in output)'
        if mode != 'json':
            print('[+] Config check is finished: \'OK\' - {}{} / \'FAIL\' - {}{}'.format(ok_count, ok_suppressed, fail_count, fail_suppressed))


def populate_simple_opt_with_data(opt, data, data_type):
    assert(opt.type != 'complex'), \
           'unexpected ComplexOptCheck "{}"'.format(opt.name)
    assert(opt.type in SIMPLE_OPTION_TYPES), \
           'invalid opt type "{}"'.format(opt.type)
    assert(data_type in SIMPLE_OPTION_TYPES), \
           'invalid data type "{}"'.format(data_type)

    if data_type != opt.type:
        return

    if data_type in ('kconfig', 'cmdline'):
        opt.state = data.get(opt.name, None)
    else:
        assert(data_type == 'version'), \
               'unexpected data type "{}"'.format(data_type)
        opt.ver = data


def populate_opt_with_data(opt, data, data_type):
    if opt.type == 'complex':
        for o in opt.opts:
            if o.type == 'complex':
                # Recursion for nested ComplexOptCheck objects
                populate_opt_with_data(o, data, data_type)
            else:
                populate_simple_opt_with_data(o, data, data_type)
    else:
        assert(opt.type in ('kconfig', 'cmdline')), \
               'bad type "{}" for a simple check'.format(opt.type)
        populate_simple_opt_with_data(opt, data, data_type)


def populate_with_data(checklist, data, data_type):
    for opt in checklist:
        populate_opt_with_data(opt, data, data_type)


def perform_checks(checklist):
    for opt in checklist:
        opt.check()


def parse_kconfig_file(parsed_options, fname):
    with open(fname, 'r') as f:
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        for line in f.readlines():
            line = line.strip()
            option = None
            value = None

            if opt_is_on.match(line):
                option, value = line.split('=', 1)
                if value == 'is not set':
                    sys.exit('[!] ERROR: bad enabled kconfig option "{}"'.format(line))
            elif opt_is_off.match(line):
                option, value = line[2:].split(' ', 1)
                if value != 'is not set':
                    sys.exit('[!] ERROR: bad disabled kconfig option "{}"'.format(line))

            if option in parsed_options:
                sys.exit('[!] ERROR: kconfig option "{}" exists multiple times'.format(line))

            if option:
                parsed_options[option] = value


def normalize_cmdline_options(option, value):
    # Don't normalize the cmdline option values if
    # the Linux kernel doesn't use kstrtobool() for them
    if option == 'debugfs':
        # See debugfs_kernel() in fs/debugfs/inode.c
        return value
    if option == 'mitigations':
        # See mitigations_parse_cmdline() in kernel/cpu.c
        return value
    if option == 'pti':
        # See pti_check_boottime_disable() in arch/x86/mm/pti.c
        return value
    if option == 'spectre_v2':
        # See spectre_v2_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'spectre_v2_user':
        # See spectre_v2_parse_user_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'spec_store_bypass_disable':
        # See ssb_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'l1tf':
        # See l1tf_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'mds':
        # See mds_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'tsx_async_abort':
        # See tsx_async_abort_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'srbds':
        # See srbds_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'mmio_stale_data':
        # See mmio_stale_data_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value
    if option == 'retbleed':
        # See retbleed_parse_cmdline() in arch/x86/kernel/cpu/bugs.c
        return value

    # Implement a limited part of the kstrtobool() logic
    if value in ('1', 'on', 'On', 'ON', 'y', 'Y', 'yes', 'Yes', 'YES'):
        return '1'
    if value in ('0', 'off', 'Off', 'OFF', 'n', 'N', 'no', 'No', 'NO'):
        return '0'

    # Preserve unique values
    return value


def parse_cmdline_file(parsed_options, fname):
    with open(fname, 'r') as f:
        line = f.readline()
        opts = line.split()

        line = f.readline()
        if line:
            sys.exit('[!] ERROR: more than one line in "{}"'.format(fname))

        for opt in opts:
            if '=' in opt:
                name, value = opt.split('=', 1)
            else:
                name = opt
                value = '' # '' is not None
            value = normalize_cmdline_options(name, value)
            parsed_options[name] = value


def main():
    # Report modes:
    #   * verbose mode for
    #     - reporting about unknown kernel options in the kconfig
    #     - verbose printing of ComplexOptCheck items
    #   * json mode for printing the results in JSON format
    report_modes = ['verbose', 'json', 'show_ok', 'show_fail']
    supported_archs = ['X86_64', 'X86_32', 'ARM64', 'ARM']
    parser = ArgumentParser(prog='kconfig-hardened-check',
                            description='A tool for checking the security hardening options of the Linux kernel')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-p', '--print', choices=supported_archs,
                        help='print security hardening preferences for the selected architecture')
    parser.add_argument('-c', '--config',
                        help='check the kernel kconfig file against these preferences')
    parser.add_argument('-l', '--cmdline',
                        help='check the kernel cmdline file against these preferences')
    parser.add_argument('-m', '--mode', choices=report_modes,
                        help='choose the report mode')
    args = parser.parse_args()

    mode = None
    if args.mode:
        mode = args.mode
        if mode != 'json':
            print('[+] Special report mode: {}'.format(mode))

    config_checklist = []

    if args.config:
        if args.print:
            sys.exit('[!] ERROR: --config and --print can\'t be used together')

        if mode != 'json':
            print('[+] Kconfig file to check: {}'.format(args.config))
            if args.cmdline:
                print('[+] Kernel cmdline file to check: {}'.format(args.cmdline))

        arch, msg = detect_arch(args.config, supported_archs)
        if not arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        if mode != 'json':
            print('[+] Detected architecture: {}'.format(arch))

        kernel_version, msg = detect_kernel_version(args.config)
        if not kernel_version:
            sys.exit('[!] ERROR: {}'.format(msg))
        if mode != 'json':
            print('[+] Detected kernel version: {}.{}'.format(kernel_version[0], kernel_version[1]))

        compiler, msg = detect_compiler(args.config)
        if mode != 'json':
            if compiler:
                print('[+] Detected compiler: {}'.format(compiler))
            else:
                print('[-] Can\'t detect the compiler: {}'.format(msg))

        # add relevant kconfig checks to the checklist
        add_kconfig_checks(config_checklist, arch)

        if args.cmdline:
            # add relevant cmdline checks to the checklist
            add_cmdline_checks(config_checklist, arch)

        # populate the checklist with the parsed kconfig data
        parsed_kconfig_options = OrderedDict()
        parse_kconfig_file(parsed_kconfig_options, args.config)
        populate_with_data(config_checklist, parsed_kconfig_options, 'kconfig')
        populate_with_data(config_checklist, kernel_version, 'version')

        if args.cmdline:
            # populate the checklist with the parsed kconfig data
            parsed_cmdline_options = OrderedDict()
            parse_cmdline_file(parsed_cmdline_options, args.cmdline)
            populate_with_data(config_checklist, parsed_cmdline_options, 'cmdline')

        # now everything is ready for performing the checks
        perform_checks(config_checklist)

        # finally print the results
        if mode == 'verbose':
            print_unknown_options(config_checklist, parsed_kconfig_options)
        print_checklist(mode, config_checklist, True)

        sys.exit(0)
    elif args.cmdline:
        sys.exit('[!] ERROR: checking cmdline doesn\'t work without checking kconfig')

    if args.print:
        if mode in ('show_ok', 'show_fail'):
            sys.exit('[!] ERROR: wrong mode "{}" for --print'.format(mode))
        arch = args.print
        add_kconfig_checks(config_checklist, arch)
        add_cmdline_checks(config_checklist, arch)
        if mode != 'json':
            print('[+] Printing kernel security hardening preferences for {}...'.format(arch))
        print_checklist(mode, config_checklist, False)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)
