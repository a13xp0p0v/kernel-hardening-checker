#!/usr/bin/python3

#
# This script helps me to check the Linux kernel Kconfig option list
# against my hardening preferences for x86_64. Let the computers do their job!
#
# Author: Alexander Popov <alex.popov@linux.com>
#
# Please don't cry if my Python code looks like C.
#

# N.B Hardening command line parameters:
#    page_poison=1
#    slub_debug=P
#    slab_nomerge
#    pti=on
#    kernel.kptr_restrict=1

import sys
from argparse import ArgumentParser
from collections import OrderedDict
import re

debug_mode = False  # set it to True to print the unknown options from the config
error_count = 0
opt_list = []


class Opt:
    def __init__(self, name, expected, decision, reason):
        self.name = name
        self.expected = expected
        self.decision = decision
        self.reason = reason
        self.state = None

    def check(self):
        global error_count
        # check parsed state against expected state
        if self.expected == self.state:
            return True, 'OK'
        if self.expected == 'is not set' and self.state == 'not found':
            return True, 'OK: not found'
        error_count += 1
        return False, 'FAIL: "' + self.state + '"'

    def __repr__(self):
        return '{} = {}'.format(self.name, self.state)


def construct_opt_checks():
    opt_list.append([Opt('BUG',                     'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('PAGE_TABLE_ISOLATION',    'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('RETPOLINE',               'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('X86_64',                  'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('STRICT_KERNEL_RWX',       'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('STRICT_MODULE_RWX',       'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('DEBUG_WX',                'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('RANDOMIZE_BASE',          'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('RANDOMIZE_MEMORY',        'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('CC_STACKPROTECTOR',       'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('VMAP_STACK',              'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('THREAD_INFO_IN_TASK',     'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('SCHED_STACK_END_CHECK',   'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('SLUB_DEBUG',              'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('SLAB_FREELIST_HARDENED',  'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('SLAB_FREELIST_RANDOM',    'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('HARDENED_USERCOPY',       'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('FORTIFY_SOURCE',          'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('MODULE_SIG',              'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('MODULE_SIG_ALL',          'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('MODULE_SIG_SHA512',       'y', 'ubuntu18', 'self_protection'), ''])
    opt_list.append([Opt('SYN_COOKIES',             'y', 'ubuntu18', 'self_protection'), '']) # another reason?
    opt_list.append([Opt('DEFAULT_MMAP_MIN_ADDR',   '65536', 'ubuntu18', 'self_protection'), ''])

    opt_list.append([Opt('BUG_ON_DATA_CORRUPTION',           'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('PAGE_POISONING',                   'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('GCC_PLUGINS',                      'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('GCC_PLUGIN_RANDSTRUCT',            'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('GCC_PLUGIN_STRUCTLEAK',            'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('GCC_PLUGIN_STRUCTLEAK_BYREF_ALL',  'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('GCC_PLUGIN_LATENT_ENTROPY',        'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('REFCOUNT_FULL',                    'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('DEBUG_LIST',                       'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('DEBUG_SG',                         'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('DEBUG_CREDENTIALS',                'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('DEBUG_NOTIFIERS',                  'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('MODULE_SIG_FORCE',                 'y', 'kspp', 'self_protection'), ''])
    opt_list.append([Opt('HARDENED_USERCOPY_FALLBACK',       'is not set', 'kspp', 'self_protection'), ''])

    opt_list.append([Opt('GCC_PLUGIN_STACKLEAK',             'y', 'my', 'self_protection'), ''])
    opt_list.append([Opt('SLUB_DEBUG_ON',                    'y', 'my', 'self_protection'), ''])
    opt_list.append([Opt('SECURITY_DMESG_RESTRICT',          'y', 'my', 'self_protection'), ''])
    opt_list.append([Opt('STATIC_USERMODEHELPER',            'y', 'my', 'self_protection'), '']) # breaks systemd?
    opt_list.append([Opt('PAGE_POISONING_NO_SANITY',         'is not set', 'my', 'self_protection'), ''])
    opt_list.append([Opt('PAGE_POISONING_ZERO',              'is not set', 'my', 'self_protection'), ''])

    opt_list.append([Opt('SECURITY',                    'y', 'ubuntu18', 'security_policy'), ''])
    opt_list.append([Opt('SECURITY_YAMA',               'y', 'ubuntu18', 'security_policy'), ''])
    opt_list.append([Opt('SECURITY_SELINUX_DISABLE',    'is not set', 'ubuntu18', 'security_policy'), ''])

    opt_list.append([Opt('SECCOMP',              'y', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('SECCOMP_FILTER',       'y', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('STRICT_DEVMEM',        'y', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('ACPI_CUSTOM_METHOD',   'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('COMPAT_BRK',           'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('DEVKMEM',              'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('COMPAT_VDSO',          'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('X86_PTDUMP',           'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('ZSMALLOC_STAT',        'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('PAGE_OWNER',           'is not set', 'ubuntu18', 'cut_attack_surface'), ''])
    opt_list.append([Opt('DEBUG_KMEMLEAK',       'is not set', 'ubuntu18', 'cut_attack_surface'), ''])

    opt_list.append([Opt('IO_STRICT_DEVMEM',     'y', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('LEGACY_VSYSCALL_NONE', 'y', 'kspp', 'cut_attack_surface'), '']) # 'vsyscall=none'
    opt_list.append([Opt('BINFMT_MISC',          'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('INET_DIAG',            'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('KEXEC',                'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('PROC_KCORE',           'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('LEGACY_PTYS',          'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('IA32_EMULATION',       'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('X86_X32',              'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('MODIFY_LDT_SYSCALL',   'is not set', 'kspp', 'cut_attack_surface'), ''])
    opt_list.append([Opt('HIBERNATION',          'is not set', 'kspp', 'cut_attack_surface'), ''])

    opt_list.append([Opt('KPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('UPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('GENERIC_TRACER',          'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('PROC_VMCORE',             'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('PROC_PAGE_MONITOR',       'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('USELIB',                  'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('CHECKPOINT_RESTORE',      'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('USERFAULTFD',             'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('HWPOISON_INJECT',         'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('MEM_SOFT_DIRTY',          'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('DEVPORT',                 'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('DEBUG_FS',                'is not set', 'grsecurity', 'cut_attack_surface'), ''])
    opt_list.append([Opt('NOTIFIER_ERROR_INJECTION','is not set', 'grsecurity', 'cut_attack_surface'), ''])

    opt_list.append([Opt('KEXEC_FILE',           'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('LIVEPATCH',            'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('USER_NS',              'is not set', 'my', 'cut_attack_surface'), '']) # user.max_user_namespaces=0
    opt_list.append([Opt('IP_DCCP',              'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('IP_SCTP',              'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('FTRACE',               'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('PROFILING',            'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('BPF_JIT',              'is not set', 'my', 'cut_attack_surface'), ''])
    opt_list.append([Opt('BPF_SYSCALL',          'is not set', 'my', 'cut_attack_surface'), ''])

    opt_list.append([Opt('ARCH_MMAP_RND_BITS',   '32', 'my', 'userspace_protection'), ''])

    opt_list.append([Opt('LKDTM',    'm', 'my', 'feature_test'), ''])


def print_opt_checks():
    print('[+] Printing kernel hardening preferences...')
    print('  {:<39}|{:^13}|{:^10}|{:^20}'.format('option name', 'desired val', 'decision', 'reason'))
    print('  ======================================================================================')
    for o in opt_list:
        print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}'.format(o[0].name, o[0].expected, o[0].decision, o[0].reason))
    print()


def print_check_results():
    global error_count

    print('  {:<39}|{:^13}|{:^10}|{:^20}||{:^20}'.format('option name', 'desired val', 'decision', 'reason', 'check result'))
    print('  ===========================================================================================================')
    for o in opt_list:
        print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}||{:^20}'.format(o[0].name, o[0].expected, o[0].decision, o[0].reason, o[1]))
    print()


def get_option_state(options, name):
    return options[name] if name in options else 'not found'


def check_state(options):
    for o in opt_list:
        opt = o[0]
        if o[1] != '':
            sys.exit('[!] BUG: CONFIG_{} was found more than once'.format(o[0].name))
        opt.state = get_option_state(options, opt.name)
        _, o[1] = opt.check()


def check_config_file(fname):
    with open(fname, 'r') as f:
        parsed_options = OrderedDict()
        opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
        opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

        print('[+] Checking "{}" against hardening preferences...'.format(fname))
        for line in f.readlines():
            line = line.strip()

            if opt_is_on.match(line):
                if line[:7] != 'CONFIG_':
                    sys.exit('[!] BUG: bad enabled config option "{}"'.format(line))

                config, value = line[7:].split('=', 1)
                parsed_options[config] = value
            elif opt_is_off.match(line):
                if line[:9] != '# CONFIG_':
                    sys.exit('[!] BUG: bad disabled config option "{}"'.format(line))

                config, value = line[9:].split(' ', 1)
                if value != 'is not set':
                    sys.exit('[!] BUG: bad disabled config option "{}"'.format(line))

                if config in parsed_options:
                    sys.exit('[!] ERROR: config option "{}" exists multiple times'.format(line))

                parsed_options[config] = value

        check_state(parsed_options)
        print_check_results()

        if debug_mode:
            opt_list_names = [opt[0].name for opt in opt_list]
            for option in filter(lambda option: option not in opt_list_names, parsed_options.keys()):
                print("DEBUG: dunno about option {} ".format(option))


if __name__ == '__main__':
    parser = ArgumentParser(description='Checks the hardening options in the Linux kernel config')
    parser.add_argument('-p', '--print', action='store_true', help='print hardening preferences')
    parser.add_argument('-c', '--config', help='check the config_file against these preferences')
    parser.add_argument('--debug', action='store_true', help='enable internal debug mode')
    args = parser.parse_args()

    construct_opt_checks()

    if args.print:
        print_opt_checks()
        sys.exit(0)

    if args.debug:
        debug_mode = True

    if args.config:
        check_config_file(args.config)
        if error_count == 0:
            print('[+] config check is PASSED')
            sys.exit(0)
        else:
            sys.exit('[-] config check is NOT PASSED: {} errors'.format(error_count))

    parser.print_help()
