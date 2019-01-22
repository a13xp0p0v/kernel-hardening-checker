#!/usr/bin/python3

#
# This script helps me to check the Linux kernel Kconfig option list
# against my hardening preferences for x86_64. Let the computers do their job!
#
# Author: Alexander Popov <alex.popov@linux.com>
#
# Please don't cry if my Python code looks like C.
#
#
# N.B Hardening command line parameters:
#    page_poison=1
#    slub_debug=FZP
#    slab_nomerge
#    pti=on
#    kernel.kptr_restrict=1
#    lockdown=1
#
#    spectre_v2=on
#    pti=on
#    spec_store_bypass_disable=on
#    l1tf=full,force
#
#
# N.B. Hardening sysctl's:
#    net.core.bpf_jit_harden
#
#
# TODO: add hardening preferences for ARM

import sys
from argparse import ArgumentParser
from collections import OrderedDict
import re

debug_mode = False  # set it to True to print the unknown options from the config

supported_archs = [ 'X86_64', 'X86_32' ]

checklist = []


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
        else:
            return False, self.result

    def __repr__(self):
        return '{} = {}'.format(self.name, self.state)


class OR:
    def __init__(self, *opts):
        self.opts = opts
        self.result = None

    # self.opts[0] is the option which this OR-check is about.
    # Use case: OR(<X_is_hardened>, <X_is_disabled>)

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

    def check(self):
        for i, opt in enumerate(self.opts):
            result, msg = opt.check()
            if result:
                if i == 0:
                    self.result = opt.result
                else:
                    self.result = 'CONFIG_{}: {} ("{}")'.format(opt.name, opt.result, opt.expected)
                return True, self.result
        self.result = self.opts[0].result
        return False, self.result


def detect_arch(fname):
    with open(fname, 'r') as f:
        arch_pattern = re.compile("CONFIG_[a-zA-Z0-9_]*=y")
        arch = None
        msg = None
        print('[+] Trying to detect architecture in "{}"...'.format(fname))
        for line in f.readlines():
            if arch_pattern.match(line):
                option, value = line[7:].split('=', 1)
                if option in supported_archs:
                    if not arch:
                        arch = option
                    else:
                        return None, 'more than one supported architecture is detected'
        if not arch:
            return None, 'failed to detect architecture'
        else:
            return arch, 'OK'


def construct_checklist(arch):
    modules_not_set = OptCheck('MODULES',                'is not set', 'kspp', 'cut_attack_surface')
    devmem_not_set = OptCheck('DEVMEM',                  'is not set', 'kspp', 'cut_attack_surface') # refers to LOCK_DOWN_KERNEL

    checklist.append(OptCheck('BUG',                         'y', 'defconfig', 'self_protection'))
    checklist.append(OptCheck('RETPOLINE',                   'y', 'defconfig', 'self_protection'))
    checklist.append(OptCheck('X86_SMAP',                    'y', 'defconfig', 'self_protection'))
    checklist.append(OptCheck('X86_INTEL_UMIP',              'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('STRICT_KERNEL_RWX',        'y', 'defconfig', 'self_protection'), \
                        OptCheck('DEBUG_RODATA',             'y', 'defconfig', 'self_protection'))) # before v4.11
    checklist.append(OptCheck('RANDOMIZE_BASE',              'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('STACKPROTECTOR_STRONG',    'y', 'defconfig', 'self_protection'), \
                        OptCheck('CC_STACKPROTECTOR_STRONG', 'y', 'defconfig', 'self_protection')))
    checklist.append(OptCheck('THREAD_INFO_IN_TASK',         'y', 'defconfig', 'self_protection'))
    checklist.append(OptCheck('SLUB_DEBUG',                  'y', 'defconfig', 'self_protection'))
    checklist.append(OR(OptCheck('STRICT_MODULE_RWX',        'y', 'defconfig', 'self_protection'), \
                        OptCheck('DEBUG_SET_MODULE_RONX',    'y', 'defconfig', 'self_protection'), \
                        modules_not_set)) # DEBUG_SET_MODULE_RONX was before v4.11
    checklist.append(OptCheck('SYN_COOKIES',                 'y', 'defconfig', 'self_protection')) # another reason?
    if arch == 'X86_64':
        checklist.append(OptCheck('PAGE_TABLE_ISOLATION',    'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('RANDOMIZE_MEMORY',        'y', 'defconfig', 'self_protection'))
        checklist.append(OptCheck('VMAP_STACK',              'y', 'defconfig', 'self_protection'))

    checklist.append(OptCheck('BUG_ON_DATA_CORRUPTION',           'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_WX',                         'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SCHED_STACK_END_CHECK',            'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('PAGE_POISONING',                   'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SLAB_FREELIST_HARDENED',           'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('SLAB_FREELIST_RANDOM',             'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('HARDENED_USERCOPY',                'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('HARDENED_USERCOPY_FALLBACK',       'is not set', 'kspp', 'self_protection'))
    checklist.append(OptCheck('FORTIFY_SOURCE',                   'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('GCC_PLUGINS',                      'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('GCC_PLUGIN_RANDSTRUCT',            'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('GCC_PLUGIN_STRUCTLEAK',            'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('GCC_PLUGIN_STRUCTLEAK_BYREF_ALL',  'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('GCC_PLUGIN_LATENT_ENTROPY',        'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('REFCOUNT_FULL',                    'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_LIST',                       'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_SG',                         'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_CREDENTIALS',                'y', 'kspp', 'self_protection'))
    checklist.append(OptCheck('DEBUG_NOTIFIERS',                  'y', 'kspp', 'self_protection'))
    checklist.append(OR(OptCheck('MODULE_SIG',                    'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OR(OptCheck('MODULE_SIG_ALL',                'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OR(OptCheck('MODULE_SIG_SHA512',             'y', 'kspp', 'self_protection'), \
                        modules_not_set))
    checklist.append(OptCheck('MODULE_SIG_FORCE',                 'y', 'kspp', 'self_protection')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('DEFAULT_MMAP_MIN_ADDR',            '65536', 'kspp', 'self_protection'))
    if arch == 'X86_32':
        checklist.append(OptCheck('HIGHMEM64G',                   'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('X86_PAE',                      'y', 'kspp', 'self_protection'))

    checklist.append(OptCheck('GCC_PLUGIN_STACKLEAK',             'y', 'my', 'self_protection'))
    checklist.append(OptCheck('LOCK_DOWN_KERNEL',                 'y', 'my', 'self_protection')) # remember about LOCK_DOWN_MANDATORY
    checklist.append(OptCheck('SLUB_DEBUG_ON',                    'y', 'my', 'self_protection'))
    checklist.append(OptCheck('SECURITY_DMESG_RESTRICT',          'y', 'my', 'self_protection'))
    checklist.append(OptCheck('STATIC_USERMODEHELPER',            'y', 'my', 'self_protection')) # breaks systemd?
    checklist.append(OptCheck('SECURITY_LOADPIN',                 'y', 'my', 'self_protection'))
    checklist.append(OptCheck('PAGE_POISONING_NO_SANITY',         'is not set', 'my', 'self_protection'))
    checklist.append(OptCheck('PAGE_POISONING_ZERO',              'is not set', 'my', 'self_protection'))
    checklist.append(OptCheck('SLAB_MERGE_DEFAULT',               'is not set', 'my', 'self_protection')) # slab_nomerge
    if arch == 'X86_32':
        checklist.append(OptCheck('PAGE_TABLE_ISOLATION',         'y', 'my', 'self_protection'))

    checklist.append(OptCheck('SECURITY',                    'y', 'defconfig', 'security_policy'))
    checklist.append(OptCheck('SECURITY_YAMA',               'y', 'kspp', 'security_policy'))
    checklist.append(OptCheck('SECURITY_SELINUX_DISABLE',    'is not set', 'kspp', 'security_policy'))

    checklist.append(OptCheck('SECCOMP',              'y', 'defconfig', 'cut_attack_surface'))
    checklist.append(OptCheck('SECCOMP_FILTER',       'y', 'defconfig', 'cut_attack_surface'))
    checklist.append(OR(OptCheck('STRICT_DEVMEM',     'y', 'defconfig', 'cut_attack_surface'), \
                        devmem_not_set)) # refers to LOCK_DOWN_KERNEL

    checklist.append(OR(OptCheck('IO_STRICT_DEVMEM',  'y', 'kspp', 'cut_attack_surface'), \
                        devmem_not_set)) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('ACPI_CUSTOM_METHOD',   'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('COMPAT_BRK',           'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('DEVKMEM',              'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('COMPAT_VDSO',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('BINFMT_MISC',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('INET_DIAG',            'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('KEXEC',                'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('PROC_KCORE',           'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('LEGACY_PTYS',          'is not set', 'kspp', 'cut_attack_surface'))
    checklist.append(OptCheck('HIBERNATION',          'is not set', 'kspp', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    if arch == 'X86_64':
        checklist.append(OptCheck('LEGACY_VSYSCALL_NONE', 'y', 'kspp', 'cut_attack_surface')) # 'vsyscall=none'
        checklist.append(OptCheck('IA32_EMULATION',       'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('X86_X32',              'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('MODIFY_LDT_SYSCALL',   'is not set', 'kspp', 'cut_attack_surface'))

    checklist.append(OptCheck('X86_PTDUMP',              'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('ZSMALLOC_STAT',           'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('PAGE_OWNER',              'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('DEBUG_KMEMLEAK',          'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('BINFMT_AOUT',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('KPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('UPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('GENERIC_TRACER',          'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('PROC_VMCORE',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('PROC_PAGE_MONITOR',       'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('USELIB',                  'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('CHECKPOINT_RESTORE',      'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('USERFAULTFD',             'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('HWPOISON_INJECT',         'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('MEM_SOFT_DIRTY',          'is not set', 'grsecurity', 'cut_attack_surface'))
    checklist.append(OptCheck('DEVPORT',                 'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('DEBUG_FS',                'is not set', 'grsecurity', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('NOTIFIER_ERROR_INJECTION','is not set', 'grsecurity', 'cut_attack_surface'))

    checklist.append(OptCheck('ACPI_TABLE_UPGRADE',   'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('ACPI_APEI_EINJ',       'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('PROFILING',            'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('BPF_SYSCALL',          'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL
    checklist.append(OptCheck('MMIOTRACE_TEST',       'is not set', 'lockdown', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL

    checklist.append(OptCheck('MMIOTRACE',            'is not set', 'my', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL (permissive)
    checklist.append(OptCheck('KEXEC_FILE',           'is not set', 'my', 'cut_attack_surface')) # refers to LOCK_DOWN_KERNEL (permissive)
    checklist.append(OptCheck('LIVEPATCH',            'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('USER_NS',              'is not set', 'my', 'cut_attack_surface')) # user.max_user_namespaces=0
    checklist.append(OptCheck('IP_DCCP',              'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('IP_SCTP',              'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('FTRACE',               'is not set', 'my', 'cut_attack_surface'))
    checklist.append(OptCheck('BPF_JIT',              'is not set', 'my', 'cut_attack_surface'))
    if arch == 'X86_32':
        checklist.append(OptCheck('MODIFY_LDT_SYSCALL', 'is not set', 'my', 'cut_attack_surface'))

    if arch == 'X86_64':
        checklist.append(OptCheck('ARCH_MMAP_RND_BITS',   '32', 'my', 'userspace_protection'))
    if arch == 'X86_32':
        checklist.append(OptCheck('ARCH_MMAP_RND_BITS',   '16', 'my', 'userspace_protection'))

#   checklist.append(OptCheck('LKDTM',    'm', 'my', 'feature_test'))


def print_checklist(arch):
    print('[+] Printing kernel hardening preferences for {}...'.format(arch))
    print('  {:<39}|{:^13}|{:^10}|{:^20}'.format(
        'option name', 'desired val', 'decision', 'reason'))
    print('  ' + '=' * 86)
    for opt in checklist:
        print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}'.format(
            opt.name, opt.expected, opt.decision, opt.reason))
    print()


def print_check_results():
    print('  {:<39}|{:^13}|{:^10}|{:^20}||{:^28}'.format(
        'option name', 'desired val', 'decision', 'reason', 'check result'))
    print('  ' + '=' * 115)
    for opt in checklist:
        print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}||{:^28}'.format(
            opt.name, opt.expected, opt.decision, opt.reason, opt.result))
    print()


def get_option_state(options, name):
    return options.get(name, None)


def perform_checks(parsed_options):
    for opt in checklist:
        if hasattr(opt, 'opts'):
            for o in opt.opts:
                o.state = get_option_state(parsed_options, o.name)
        else:
            opt.state = get_option_state(parsed_options, opt.name)
        opt.check()


def check_config_file(fname):
    with open(fname, 'r') as f:
        parsed_options = OrderedDict()
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        print('[+] Checking "{}" against hardening preferences...'.format(fname))
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

        perform_checks(parsed_options)

        if debug_mode:
            known_options = [opt.name for opt in checklist]
            for option, value in parsed_options.items():
                if option not in known_options:
                    print("DEBUG: dunno about option {} ({})".format(option, value))

        print_check_results()


if __name__ == '__main__':
    parser = ArgumentParser(description='Checks the hardening options in the Linux kernel config')
    parser.add_argument('-p', '--print', choices=supported_archs,
                        help='print hardening preferences for selected architecture')
    parser.add_argument('-c', '--config',
                        help='check the config_file against these preferences')
    parser.add_argument('--debug', action='store_true',
                        help='enable internal debug mode')
    args = parser.parse_args()

    if args.debug:
        debug_mode = True

    if args.config:
        arch, msg = detect_arch(args.config)
        if not arch:
            sys.exit('[!] ERROR: {}'.format(msg))
        else:
            print('[+] Detected architecture: {}'.format(arch))

        construct_checklist(arch)
        check_config_file(args.config)
        error_count = len(list(filter(lambda opt: opt.result.startswith('FAIL'), checklist)))
        if error_count == 0:
            print('[+] config check is PASSED')
            sys.exit(0)
        else:
            sys.exit('[-] config check is NOT PASSED: {} errors'.format(error_count))

    if args.print:
        arch = args.print
        construct_checklist(arch)
        print_checklist(arch)
        sys.exit(0)

    parser.print_help()
