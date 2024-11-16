#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
SPDX-License-Identifier: GPL-3.0-only

This module performs input/output.
"""

# pylint: disable=missing-function-docstring,line-too-long,too-many-branches,too-many-statements

import os
import gzip
import sys
import tempfile
import subprocess
from argparse import ArgumentParser
from typing import List, Tuple, Dict, TextIO, Any
import re
import json
from .checks import add_kconfig_checks, add_cmdline_checks, normalize_cmdline_options, add_sysctl_checks
from .engine import StrOrNone, TupleOrNone, ChecklistObjType
from .engine import print_unknown_options, populate_with_data, perform_checks, override_expected_value


# kernel-hardening-checker version
__version__ = '0.6.10'

SUPPORTED_ARCHS = ['X86_64', 'X86_32', 'ARM64', 'ARM']


def mprint(mode: StrOrNone, *args: Any, **kwargs: Any) -> None:
    if mode != 'json':
        print(*args, **kwargs)


def _open(file: str) -> TextIO:
    try:
        if file.endswith('.gz'):
            return gzip.open(file, 'rt', encoding='utf-8')
        return open(file, 'rt', encoding='utf-8')
    except FileNotFoundError:
        sys.exit(f'[!] ERROR: unable to open {file}, are you sure it exists?')
    except PermissionError:
        sys.exit(f'[!] ERROR: unable to open {file}, permission denied')


def detect_kconfig(version_fname: str) -> Tuple[StrOrNone, str]:
    kconfig_1 = '/proc/config.gz'
    if os.path.isfile(kconfig_1):
        return kconfig_1, 'OK'

    kconfig_2 = '/boot/config-'
    with _open(version_fname) as f:
        line = f.readline()
        assert(line), f'empty {version_fname}'
        assert(line.startswith('Linux version ')), f'unexpected contents of {version_fname}'
        parts = line.split()
        ver_str = parts[2]
        kconfig_2 = kconfig_2 + ver_str
    if os.path.isfile(kconfig_2):
        return kconfig_2, 'OK'

    return None, f'didn\'t find {kconfig_1} or {kconfig_2}'


def detect_arch_by_kconfig(fname: str) -> Tuple[StrOrNone, str]:
    arch = None

    with _open(fname) as f:
        for line in f.readlines():
            if m := re.search("CONFIG_([A-Z0-9_]+)=y$", line):
                option = m.group(1)
                if option not in SUPPORTED_ARCHS:
                    continue
                if arch is None:
                    arch = option
                else:
                    return None, 'detected more than one microarchitecture in kconfig'

    if arch is None:
        return None, 'failed to detect microarchitecture in kconfig'
    return arch, 'OK'


def detect_arch_by_sysctl(fname: str) -> Tuple[StrOrNone, str]:
    arch_mapping = {
        'ARM64': r'^aarch64|armv8',
        'ARM': r'^armv[3-7]',
        'X86_32': r'^i[3-6]?86',
        'X86_64': r'^x86_64'
    }
    with _open(fname) as f:
        for line in f.readlines():
            if line.startswith('kernel.arch'):
                value = line.split('=', 1)[1].strip()
                for arch, pattern in arch_mapping.items():
                    assert(arch in SUPPORTED_ARCHS), 'invalid arch mapping in sysctl'
                    if re.search(pattern, value):
                        return arch, value
                return None, f'{value} is an unsupported arch'
        return None, 'failed to detect microarchitecture in sysctl'


def detect_kernel_version(fname: str) -> Tuple[TupleOrNone, str]:
    with _open(fname) as f:
        ver_pattern = re.compile(r"^# Linux/.+ Kernel Configuration$|^Linux version .+")
        for line in f.readlines():
            if ver_pattern.match(line):
                line = line.strip()
                parts = line.split()
                ver_str = parts[2].split('-', 1)[0]
                ver_numbers = ver_str.split('.')
                if len(ver_numbers) >= 3:
                    if all(map(lambda x: x.isdecimal(), ver_numbers)):
                        return tuple(map(int, ver_numbers)), 'OK'
                msg = f'failed to parse the version "{parts[2]}"'
                return None, msg
        return None, 'no kernel version detected'


def detect_compiler(fname: str) -> Tuple[StrOrNone, str]:
    gcc_version = None
    clang_version = None
    with _open(fname) as f:
        for line in f.readlines():
            if line.startswith('CONFIG_GCC_VERSION='):
                gcc_version = line[19:-1]
            if line.startswith('CONFIG_CLANG_VERSION='):
                clang_version = line[21:-1]
    if gcc_version is None or clang_version is None:
        return None, 'no CONFIG_GCC_VERSION or CONFIG_CLANG_VERSION'
    if gcc_version == '0' and clang_version != '0':
        return f'CLANG {clang_version}', 'OK'
    if gcc_version != '0' and clang_version == '0':
        return f'GCC {gcc_version}', 'OK'
    sys.exit(f'[!] ERROR: invalid GCC_VERSION and CLANG_VERSION: {gcc_version} {clang_version}')


def print_checklist(mode: StrOrNone, checklist: List[ChecklistObjType], with_results: bool) -> None:
    if mode == 'json':
        output = []
        for opt in checklist:
            output.append(opt.json_dump(with_results))
        print(json.dumps(output))
        return

    # table header
    sep_line_len = 91
    if with_results:
        sep_line_len += 30
    print('=' * sep_line_len)
    print(f'{"option_name":^40}|{"type":^7}|{"desired_val":^12}|{"decision":^10}|{"reason":^18}', end='')
    if with_results:
        print('| check_result', end='')
    print()
    print('=' * sep_line_len)

    # table contents
    ok_count = 0
    fail_count = 0
    for opt in checklist:
        if with_results:
            assert(opt.result), f'unexpected empty result of {opt.name} check'
            if opt.result.startswith('OK'):
                ok_count += 1
                if mode == 'show_fail':
                    continue
            else:
                assert(opt.result.startswith('FAIL')), \
                       f'unexpected result "{opt.result}" of {opt.name} check'
                fail_count += 1
                if mode == 'show_ok':
                    continue
        opt.table_print(mode, with_results)
        print()
        if mode == 'verbose':
            print('-' * sep_line_len)
    print()

    # final score
    if with_results:
        fail_suppressed = ''
        ok_suppressed = ''
        if mode == 'show_ok':
            fail_suppressed = ' (suppressed in output)'
        if mode == 'show_fail':
            ok_suppressed = ' (suppressed in output)'
        print(f'[+] Config check is finished: \'OK\' - {ok_count}{ok_suppressed} / \'FAIL\' - {fail_count}{fail_suppressed}')


def parse_kconfig_file(_mode: StrOrNone, parsed_options: Dict[str, str], fname: str) -> None:
    with _open(fname) as f:
        opt_is_on = re.compile(r"CONFIG_[a-zA-Z0-9_]+=.*$")
        opt_is_off = re.compile(r"# CONFIG_[a-zA-Z0-9_]+ is not set$")

        for line in f.readlines():
            line = line.strip()
            option = None
            value = None

            if opt_is_on.match(line):
                option, value = line.split('=', 1)
                if value == 'is not set':
                    sys.exit(f'[!] ERROR: bad enabled Kconfig option "{line}"')
                if value == '':
                    print(f'[!] WARNING: found strange Kconfig option {option} with empty value')
            elif opt_is_off.match(line):
                option, value = line[2:].split(' ', 1)
                assert(value == 'is not set'), \
                       f'unexpected value of disabled Kconfig option "{line}"'
            elif line != '' and not line.startswith('#'):
                sys.exit(f'[!] ERROR: unexpected line in Kconfig file: "{line}"')

            if option in parsed_options:
                sys.exit(f'[!] ERROR: Kconfig option "{line}" is found multiple times')

            if option:
                assert(value is not None), f'unexpected None value for {option}'
                parsed_options[option] = value


def parse_cmdline_file(mode: StrOrNone, parsed_options: Dict[str, str], fname: str) -> None:
    with _open(fname) as f:
        line = f.readline()
        if not line:
            sys.exit(f'[!] ERROR: empty cmdline file "{fname}"')

        opts = line.split()

        line = f.readline()
        if line:
            sys.exit(f'[!] ERROR: more than one line in "{fname}"')

        for opt in opts:
            if '=' in opt:
                name, value = opt.split('=', 1)
            else:
                name = opt
                value = '' # '' is not None
            if name in parsed_options and mode != 'json':
                print(f'[!] WARNING: cmdline option "{name}" is found multiple times')
            value = normalize_cmdline_options(name, value)
            assert(value is not None), f'unexpected None value for {name}'
            parsed_options[name] = value


def parse_sysctl_file(mode: StrOrNone, parsed_options: Dict[str, str], fname: str) -> None:
    with _open(fname) as f:
        if os.stat(fname).st_size == 0:
            sys.exit(f'[!] ERROR: empty sysctl file "{fname}"')

        sysctl_pattern = re.compile(r"[a-zA-Z0-9/\._-]+ ?=.*$")
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if not sysctl_pattern.match(line):
                sys.exit(f'[!] ERROR: unexpected line in sysctl file: "{line}"')
            option, value = line.split('=', 1)
            option = option.strip()
            value = value.strip()
            # sysctl options may be found multiple times, let's save the last value:
            parsed_options[option] = value

    # let's check the presence of some ancient sysctl option
    # to ensure that we are parsing the output of `sudo sysctl -a > file`
    if 'kernel.printk' not in parsed_options and mode != 'json':
        print(f'[!] WARNING: ancient sysctl options are not found in {fname}, try checking the output of `sudo sysctl -a`')

    # let's check the presence of a sysctl option available for root
    if 'kernel.cad_pid' not in parsed_options and mode != 'json':
        print(f'[!] WARNING: sysctl options available for root are not found in {fname}, try checking the output of `sudo sysctl -a`')


def refine_check(mode: StrOrNone, checklist: List[ChecklistObjType], parsed_options: Dict[str, str],
                 target: str, source: str) -> None:
    source_val = parsed_options.get(source, None)
    if source_val:
        override_expected_value(checklist, target, source_val)
    else:
        # remove the target check to avoid false results
        mprint(mode, f'[-] Can\'t check {target} without {source}')
        checklist[:] = [o for o in checklist if o.name != target]


def perform_checking(mode: StrOrNone, version: TupleOrNone,
                     kconfig: StrOrNone, cmdline: StrOrNone, sysctl: StrOrNone) -> None:
    config_checklist = [] # type: List[ChecklistObjType]
    arch = None

    # detect the kernel microarchitecture
    if kconfig:
        arch, msg = detect_arch_by_kconfig(kconfig)
        if arch is None:
            sys.exit(f'[!] ERROR: {msg}')
        mprint(mode, f'[+] Detected microarchitecture: {arch}')
    else:
        assert(not cmdline), 'wrong perform_checking() usage'
        assert(sysctl), 'wrong perform_checking() usage'
        arch, msg = detect_arch_by_sysctl(sysctl)
        if arch is None:
            mprint(mode, f'[!] WARNING: {msg}, arch-dependent checks will be dropped')
        else:
            mprint(mode, f'[+] Detected microarchitecture: {arch} ({msg})')

    if kconfig:
        # kconfig allows to determine the compiler for building the kernel
        compiler, msg = detect_compiler(kconfig)
        if compiler:
            mprint(mode, f'[+] Detected compiler: {compiler}')
        else:
            mprint(mode, f'[-] Can\'t detect the compiler: {msg}')

    if kconfig:
        # add relevant Kconfig checks to the checklist
        assert(arch), 'arch is mandatory for the kconfig checks'
        add_kconfig_checks(config_checklist, arch)

    if cmdline:
        # add relevant cmdline checks to the checklist
        assert(arch), 'arch is mandatory for the cmdline checks'
        add_cmdline_checks(config_checklist, arch)

    if sysctl:
        # add relevant sysctl checks to the checklist
        add_sysctl_checks(config_checklist, arch)

    if version:
        # populate the checklist with the kernel version data
        populate_with_data(config_checklist, version, 'version')

    parsed_kconfig_options = {} # type: Dict[str, str]
    if kconfig:
        # populate the checklist with the parsed Kconfig data
        parse_kconfig_file(mode, parsed_kconfig_options, kconfig)
        populate_with_data(config_checklist, parsed_kconfig_options, 'kconfig')
        # refine the values of some checks
        refine_check(mode, config_checklist, parsed_kconfig_options,
                     'CONFIG_ARCH_MMAP_RND_BITS', 'CONFIG_ARCH_MMAP_RND_BITS_MAX')
        refine_check(mode, config_checklist, parsed_kconfig_options,
                     'CONFIG_ARCH_MMAP_RND_COMPAT_BITS', 'CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX')
        # and don't forget to skip these Kconfig checks in --generate

    if cmdline:
        # populate the checklist with the parsed cmdline data
        parsed_cmdline_options = {} # type: Dict[str, str]
        parse_cmdline_file(mode, parsed_cmdline_options, cmdline)
        populate_with_data(config_checklist, parsed_cmdline_options, 'cmdline')

    if sysctl:
        # populate the checklist with the parsed sysctl data
        parsed_sysctl_options = {} # type: Dict[str, str]
        parse_sysctl_file(mode, parsed_sysctl_options, sysctl)
        populate_with_data(config_checklist, parsed_sysctl_options, 'sysctl')
        # refine the values of some checks
        refine_check(mode, config_checklist, parsed_kconfig_options,
                     'vm.mmap_rnd_bits', 'CONFIG_ARCH_MMAP_RND_BITS_MAX')
        refine_check(mode, config_checklist, parsed_kconfig_options,
                     'vm.mmap_rnd_compat_bits', 'CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX')

    # now everything is ready, perform the checks
    perform_checks(config_checklist)

    if mode == 'verbose':
        # print the parsed options without the checks (for debugging)
        if kconfig:
            print_unknown_options(config_checklist, parsed_kconfig_options, 'kconfig')
        if cmdline:
            print_unknown_options(config_checklist, parsed_cmdline_options, 'cmdline')
        if sysctl:
            print_unknown_options(config_checklist, parsed_sysctl_options, 'sysctl')

    # finally print the results
    print_checklist(mode, config_checklist, True)


def main() -> None:
    # Report modes:
    #   * verbose mode for
    #     - reporting about unknown kernel options in the Kconfig
    #     - verbose printing of ComplexOptCheck items
    #   * json mode for printing the results in JSON format
    report_modes = ['verbose', 'json', 'show_ok', 'show_fail']
    parser = ArgumentParser(prog='kernel-hardening-checker',
                            description='A tool for checking the security hardening options of the Linux kernel')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('-m', '--mode', choices=report_modes,
                        help='choose the report mode')
    parser.add_argument('-a', '--autodetect', action='store_true',
                        help='autodetect and check the security hardening options of the running kernel')
    parser.add_argument('-c', '--config',
                        help='check the security hardening options in the Kconfig file (also supports *.gz files)')
    parser.add_argument('-v', '--kernel-version',
                        help='extract version from the kernel version file (contents of /proc/version) instead of Kconfig file')
    parser.add_argument('-l', '--cmdline',
                        help='check the security hardening options in the kernel cmdline file (contents of /proc/cmdline)')
    parser.add_argument('-s', '--sysctl',
                        help='check the security hardening options in the sysctl output file (`sudo sysctl -a > file`)')
    parser.add_argument('-p', '--print', choices=SUPPORTED_ARCHS,
                        help='print the security hardening recommendations for the selected microarchitecture')
    parser.add_argument('-g', '--generate', choices=SUPPORTED_ARCHS,
                        help='generate a Kconfig fragment with the security hardening options for the selected microarchitecture')
    args = parser.parse_args()

    mode = None
    if args.mode:
        mode = args.mode
        mprint(mode, f'[+] Special report mode: {mode}')

    if args.autodetect:
        if args.config or args.kernel_version or args.cmdline or args.sysctl:
            sys.exit('[!] ERROR: --autodetect should find the configuration, no other arguments are needed')
        if args.print:
            sys.exit('[!] ERROR: --autodetect and --print can\'t be used together')
        if args.generate:
            sys.exit('[!] ERROR: --autodetect and --generate can\'t be used together')

        mprint(mode, '[+] Going to autodetect and check the security hardening options of the running kernel')

        version_file = '/proc/version'
        kernel_version, msg = detect_kernel_version(version_file)
        if kernel_version is None:
            sys.exit(f'[!] ERROR: parsing {version_file} failed: {msg}')
        mprint(mode, f'[+] Detected version of the running kernel: {kernel_version}')

        kconfig_file, msg = detect_kconfig(version_file)
        if kconfig_file is None:
            sys.exit(f'[!] ERROR: detecting kconfig file failed: {msg}')
        mprint(mode, f'[+] Detected kconfig file of the running kernel: {kconfig_file}')

        cmdline_file = '/proc/cmdline'
        if not os.path.isfile(cmdline_file):
            sys.exit(f'[!] ERROR: no kernel cmdline file {cmdline_file}')
        mprint(mode, f'[+] Detected cmdline parameters of the running kernel: {cmdline_file}')

        _, sysctl_file = tempfile.mkstemp(prefix='sysctl-')
        with open(sysctl_file, 'w', encoding='utf-8') as f:
            ret = subprocess.run(['sysctl', '-a'], check=False, stdout=f, stderr=subprocess.DEVNULL, shell=False).returncode
            if ret != 0:
                sys.exit(f'[!] ERROR: sysctl command returned {ret}')
        mprint(mode, f'[+] Saved sysctl output to {sysctl_file}')

        perform_checking(mode, kernel_version, kconfig_file, cmdline_file, sysctl_file)

        os.remove(sysctl_file)
        sys.exit(0)

    if args.config:
        mprint(mode, f'[+] Kconfig file to check: {args.config}')
    if args.cmdline:
        mprint(mode, f'[+] Kernel cmdline file to check: {args.cmdline}')
    if args.sysctl:
        mprint(mode, f'[+] Sysctl output file to check: {args.sysctl}')

    if args.config:
        assert(not args.autodetect), 'unexpected args'
        if args.print:
            sys.exit('[!] ERROR: --config and --print can\'t be used together')
        if args.generate:
            sys.exit('[!] ERROR: --config and --generate can\'t be used together')

        if args.kernel_version:
            kernel_version, msg = detect_kernel_version(args.kernel_version)
        else:
            kernel_version, msg = detect_kernel_version(args.config)
        if kernel_version is None:
            if args.kernel_version is None:
                print('[!] Hint: provide the kernel version file through --kernel-version option')
            sys.exit(f'[!] ERROR: {msg}')
        mprint(mode, f'[+] Detected kernel version: {kernel_version}')

        perform_checking(mode, kernel_version, args.config, args.cmdline, args.sysctl)
        sys.exit(0)
    elif args.cmdline:
        sys.exit('[!] ERROR: checking cmdline depends on checking Kconfig')
    elif args.sysctl:
        # separate sysctl checking (without kconfig)
        assert(not args.autodetect), 'unexpected args'
        if args.kernel_version:
            sys.exit('[!] ERROR: --kernel-version is not needed for --sysctl')
        if args.print:
            sys.exit('[!] ERROR: --sysctl and --print can\'t be used together')
        if args.generate:
            sys.exit('[!] ERROR: --sysctl and --generate can\'t be used together')
        perform_checking(mode, None, None, None, args.sysctl)
        sys.exit(0)

    if args.print:
        assert(not args.autodetect and
               args.config is None and
               args.cmdline is None and
               args.sysctl is None), \
               'unexpected args'
        if args.kernel_version:
            sys.exit('[!] ERROR: --kernel-version is not needed for --print')
        if args.generate:
            sys.exit('[!] ERROR: --print and --generate can\'t be used together')
        if mode and mode not in ('verbose', 'json'):
            sys.exit(f'[!] ERROR: wrong mode "{mode}" for --print')
        arch = args.print
        assert(arch), 'unexpected empty arch from ArgumentParser'
        config_checklist = [] # type: List[ChecklistObjType]
        add_kconfig_checks(config_checklist, arch)
        add_cmdline_checks(config_checklist, arch)
        add_sysctl_checks(config_checklist, arch)
        mprint(mode, f'[+] Printing kernel security hardening options for {arch}...')
        print_checklist(mode, config_checklist, False)
        sys.exit(0)

    if args.generate:
        assert(not args.autodetect and
               args.config is None and
               args.cmdline is None and
               args.sysctl is None and
               args.print is None), \
               'unexpected args'
        if mode:
            sys.exit(f'[!] ERROR: wrong mode "{mode}" for --generate')
        if args.kernel_version:
            sys.exit('[!] ERROR: --kernel-version is not needed for --generate')
        arch = args.generate
        config_checklist = []
        add_kconfig_checks(config_checklist, arch)
        print(f'CONFIG_{arch}=y') # the Kconfig fragment should describe the microarchitecture
        for opt in config_checklist:
            if opt.name in ('CONFIG_ARCH_MMAP_RND_BITS', 'CONFIG_ARCH_MMAP_RND_COMPAT_BITS'):
                continue # don't add Kconfig options with a value that needs refinement
            if opt.expected == 'is not off':
                continue # don't add Kconfig options without explicitly recommended values
            if opt.expected == 'is not set':
                print(f'# {opt.name} is not set')
            else:
                print(f'{opt.name}={opt.expected}')
        sys.exit(0)

    parser.print_help()
    sys.exit(0)
