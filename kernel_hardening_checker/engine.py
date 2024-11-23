#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
SPDX-License-Identifier: GPL-3.0-only

This module is the engine of checks.
"""

# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=line-too-long,too-many-branches

from __future__ import annotations
import sys

from typing import Union, Optional, List, Dict, Tuple
StrOrNone = Optional[str]
TupleOrNone = Optional[Tuple[int, ...]]
DictOrTuple = Union[Dict[str, str], Tuple[int, ...]]
StrOrBool = Union[str, bool]

GREEN_COLOR = '\x1b[32m'
RED_COLOR = '\x1b[31m'
COLOR_END = '\x1b[0m'


def colorize_result(input_text: StrOrNone) -> StrOrNone:
    if input_text is None or not sys.stdout.isatty():
        return input_text
    if input_text.startswith('OK'):
        color = GREEN_COLOR
    else:
        assert(input_text.startswith('FAIL:')), f'unexpected result "{input_text}"'
        color = RED_COLOR
    return f'{color}{input_text}{COLOR_END}'


class OptCheck:
    def __init__(self, reason: str, decision: str, name: str, expected: str) -> None:
        assert(name and isinstance(name, str) and
               name == name.strip() and len(name.split()) == 1), \
               f'invalid name "{name}" for {self.__class__.__name__}'
        self.name = name

        assert(decision and isinstance(decision, str) and
               decision == decision.strip() and len(decision.split()) == 1), \
               f'invalid decision "{decision}" for "{name}" check'
        self.decision = decision

        assert(reason and isinstance(reason, str) and
               reason == reason.strip() and len(reason.split()) == 1), \
               f'invalid reason "{reason}" for "{name}" check'
        self.reason = reason

        assert(expected and isinstance(expected, str) and expected == expected.strip()), \
               f'invalid expected value "{expected}" for "{name}" check (1)'
        val_len = len(expected.split())
        if val_len == 3:
            assert(expected in ('is not set', 'is not off')), \
                   f'invalid expected value "{expected}" for "{name}" check (2)'
        elif val_len == 2:
            assert(expected == 'is present'), \
                   f'invalid expected value "{expected}" for "{name}" check (3)'
        else:
            assert(val_len == 1), \
                   f'invalid expected value "{expected}" for "{name}" check (4)'
        self.expected = expected

        self.state = None # type: str | None
        self.result = None # type: str | None

    @property
    def opt_type(self) -> StrOrNone:
        raise NotImplementedError # pragma: no cover

    def set_state(self, data: StrOrNone) -> None:
        assert(data is None or isinstance(data, str)), \
               f'invalid state "{data}" for "{self.name}" check'
        self.state = data

    def check(self) -> None:
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
            elif self.state in ('0', 'is not set'):
                self.result = f'FAIL: is off, "{self.state}"'
            elif self.state is None:
                self.result = 'FAIL: is off, not found'
            else:
                self.result = f'OK: is not off, "{self.state}"'
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
            self.result = f'FAIL: "{self.state}"'

    def table_print(self, _mode: StrOrNone, with_results: bool) -> None:
        print(f'{self.name:<40}|{self.opt_type:^7}|{self.expected:^12}|{self.decision:^10}|{self.reason:^18}', end='')
        if with_results:
            print(f'| {colorize_result(self.result)}', end='')

    def json_dump(self, with_results: bool) -> Dict[str, StrOrBool]:
        assert(self.opt_type), f'unexpected empty opt_type in {self.name}'
        dump = {
            'option_name': self.name,
            'type': self.opt_type,
            'desired_val': self.expected,
            'decision': self.decision,
            'reason': self.reason,
        } # type: Dict[str, StrOrBool]
        if with_results:
            assert(self.result), f'unexpected empty result in {self.name}'
            dump['check_result'] = self.result
            dump['check_result_bool'] = self.result.startswith('OK')
        return dump


class KconfigCheck(OptCheck):
    def __init__(self, *args: str) -> None:
        super().__init__(*args)
        self.name = f'CONFIG_{self.name}'

    @property
    def opt_type(self) -> str:
        return 'kconfig'


class CmdlineCheck(OptCheck):
    @property
    def opt_type(self) -> str:
        return 'cmdline'


class SysctlCheck(OptCheck):
    @property
    def opt_type(self) -> str:
        return 'sysctl'


class VersionCheck:
    def __init__(self, ver_expected: Tuple[int, int, int]) -> None:
        assert(ver_expected and isinstance(ver_expected, tuple) and len(ver_expected) == 3), \
               f'invalid expected version "{ver_expected}" for VersionCheck (1)'
        assert(all(map(lambda x: isinstance(x, int), ver_expected))), \
               f'invalid expected version "{ver_expected}" for VersionCheck (2)'
        self.ver_expected = ver_expected
        self.ver = (0, 0, 0) # type: Tuple[int, ...]
        self.result = None # type: str | None

    @property
    def opt_type(self) -> str:
        return 'version'

    def set_state(self, data: Tuple[int, ...]) -> None:
        assert(data and isinstance(data, tuple) and len(data) >= 3), \
               f'invalid version "{data}" for VersionCheck (1)'
        assert(all(map(lambda x: isinstance(x, int), data))), \
               f'invalid version "{data}" for VersionCheck (2)'
        self.ver = data[:3]

    def check(self) -> None:
        assert(self.ver[0] >= 2), 'not initialized kernel version'
        if self.ver[0] > self.ver_expected[0]:
            self.result = f'OK: version >= {self.ver_expected}'
            return
        if self.ver[0] < self.ver_expected[0]:
            self.result = f'FAIL: version < {self.ver_expected}'
            return
        # self.ver[0] and self.ver_expected[0] are equal
        if self.ver[1] > self.ver_expected[1]:
            self.result = f'OK: version >= {self.ver_expected}'
            return
        if self.ver[1] < self.ver_expected[1]:
            self.result = f'FAIL: version < {self.ver_expected}'
            return
        # self.ver[1] and self.ver_expected[1] are equal too
        if self.ver[2] >= self.ver_expected[2]:
            self.result = f'OK: version >= {self.ver_expected}'
            return
        self.result = f'FAIL: version < {self.ver_expected}'

    def table_print(self, _mode: StrOrNone, with_results: bool) -> None:
        ver_req = f'kernel version >= {self.ver_expected}'
        print(f'{ver_req:<91}', end='')
        if with_results:
            print(f'| {colorize_result(self.result)}', end='')


class ComplexOptCheck:
    def __init__(self, *opts: AnyOptCheckType) -> None:
        self.opts = opts
        assert(self.opts), \
               f'empty {self.__class__.__name__} check'
        assert(len(self.opts) != 1), \
               f'useless {self.__class__.__name__} check: {opts}'
        assert(isinstance(self.opts[0], SimpleNamedOptCheckTypes)), \
               f'invalid {self.__class__.__name__} check: {opts}'
        self.result = None # type: str | None

    @property
    def opt_type(self) -> str:
        return 'complex'

    @property
    def name(self) -> str:
        assert hasattr(self.opts[0], 'name') # true for SimpleNamedOptCheckTypes
        return self.opts[0].name

    @property
    def expected(self) -> str:
        assert hasattr(self.opts[0], 'expected') # true for SimpleNamedOptCheckTypes
        return self.opts[0].expected

    def check(self) -> None:
        raise NotImplementedError # pragma: no cover

    def table_print(self, mode: StrOrNone, with_results: bool) -> None:
        if mode == 'verbose':
            class_name = f'<<< {self.__class__.__name__} >>>'
            print(f'    {class_name:87}', end='')
            if with_results:
                print(f'| {colorize_result(self.result)}', end='')
            for o in self.opts:
                print()
                o.table_print(mode, with_results)
        else:
            o = self.opts[0]
            o.table_print(mode, False)
            if with_results:
                print(f'| {colorize_result(self.result)}', end='')

    def json_dump(self, with_results: bool) -> Dict[str, StrOrBool]:
        assert hasattr(self.opts[0], 'json_dump') # true for SimpleNamedOptCheckTypes
        dump = self.opts[0].json_dump(False)
        if with_results:
            # Add the 'check_result' and 'check_result_bool' keys to the dictionary
            assert(self.result), f'unexpected empty result in {self.name}'
            dump['check_result'] = self.result
            dump['check_result_bool'] = self.result.startswith('OK')
        return dump


class OR(ComplexOptCheck):
    # self.opts[0] is the option that this OR-check is about.
    # Use cases:
    #     OR(<X_is_hardened>, <X_is_disabled>)
    #     OR(<X_is_hardened>, <old_X_is_hardened>)
    def check(self) -> None:
        for i, opt in enumerate(self.opts):
            opt.check()
            assert(opt.result), 'unexpected empty result of the OR sub-check'
            if opt.result.startswith('OK'):
                self.result = opt.result
                if i != 0:
                    # Add more info for additional checks:
                    if isinstance(opt, VersionCheck):
                        assert(opt.result.startswith('OK: version')), \
                               f'unexpected VersionCheck result {opt.result}'
                        # VersionCheck provides enough info, nothing to add
                    else:
                        if opt.result == 'OK':
                            self.result = f'OK: {opt.name} is "{opt.expected}"'
                        elif opt.result == 'OK: is not found':
                            self.result = f'OK: {opt.name} is not found'
                        elif opt.result == 'OK: is present':
                            self.result = f'OK: {opt.name} is present'
                        else:
                            assert(opt.result.startswith('OK: is not off')), \
                                   f'unexpected OK description "{opt.result}"'
                            self.result = f'OK: {opt.name} is not off'
                return
        self.result = self.opts[0].result


class AND(ComplexOptCheck):
    # self.opts[0] is the option that this AND-check is about.
    # Use cases:
    #     AND(<suboption>, <main_option>)
    #       Suboption is not checked if checking of the main_option is failed.
    #     AND(<X_is_disabled>, <old_X_is_disabled>)
    def check(self) -> None:
        for i, opt in reversed(list(enumerate(self.opts))):
            opt.check()
            assert(opt.result), 'unexpected empty result of the AND sub-check'
            if i == 0:
                self.result = opt.result
                return
            if not opt.result.startswith('OK'):
                # This FAIL is caused by additional checks,
                # and not by the main option that this AND-check is about.
                # Describe the reason of the FAIL.
                if isinstance(opt, VersionCheck):
                    assert(opt.result.startswith('FAIL: version')), \
                           f'unexpected VersionCheck result {opt.result}'
                    self.result = opt.result # VersionCheck provides enough info
                else:
                    if opt.result.startswith('FAIL: \"') or opt.result == 'FAIL: is not found':
                        self.result = f'FAIL: {opt.name} is not "{opt.expected}"'
                    elif opt.result == 'FAIL: is not present':
                        self.result = f'FAIL: {opt.name} is not present'
                    elif opt.result in ('FAIL: is off', 'FAIL: is off, "0"', 'FAIL: is off, "is not set"'):
                        self.result = f'FAIL: {opt.name} is off'
                    else:
                        assert(opt.result == 'FAIL: is off, not found'), \
                               f'unexpected FAIL description "{opt.result}"'
                        self.result = f'FAIL: {opt.name} is off, not found'
                return


# All classes are declared, let's define typing:
#  1) basic simple check objects
SIMPLE_OPTION_TYPES = ('kconfig', 'cmdline', 'sysctl', 'version')
SimpleOptCheckType = Union[KconfigCheck, CmdlineCheck, SysctlCheck, VersionCheck]
SimpleOptCheckTypes = (KconfigCheck, CmdlineCheck, SysctlCheck, VersionCheck)
SimpleNamedOptCheckType = Union[KconfigCheck, CmdlineCheck, SysctlCheck]
SimpleNamedOptCheckTypes = (KconfigCheck, CmdlineCheck, SysctlCheck)

#  2) complex objects that may contain complex and simple objects
ComplexOptCheckType = Union[OR, AND]
ComplexOptCheckTypes = (OR, AND)

#  3) objects that can be added to the checklist
ChecklistObjType = Union[KconfigCheck, CmdlineCheck, SysctlCheck, OR, AND]

#  4) all existing objects
AnyOptCheckType = Union[KconfigCheck, CmdlineCheck, SysctlCheck, VersionCheck, OR, AND]


def populate_simple_opt_with_data(opt: SimpleOptCheckType, data: DictOrTuple, data_type: str) -> None:
    assert(opt.opt_type != 'complex'), f'unexpected opt_type "{opt.opt_type}" for {opt}'
    assert(opt.opt_type in SIMPLE_OPTION_TYPES), f'invalid opt_type "{opt.opt_type}"'
    assert(data_type in SIMPLE_OPTION_TYPES), f'invalid data_type "{data_type}"'

    if data_type != opt.opt_type:
        return

    if data_type in ('kconfig', 'cmdline', 'sysctl'):
        assert(isinstance(data, dict)), \
               f'unexpected data with data_type {data_type}'
        assert(isinstance(opt, SimpleNamedOptCheckTypes)), \
               f'unexpected VersionCheck with opt_type "{opt.opt_type}"'
        opt.set_state(data.get(opt.name, None))
    else:
        assert(isinstance(data, tuple)), \
               f'unexpected verion data with data_type {data_type}'
        assert(isinstance(opt, VersionCheck) and data_type == 'version'), \
               f'unexpected data_type "{data_type}"'
        opt.set_state(data)


def populate_opt_with_data(opt: AnyOptCheckType, data: DictOrTuple, data_type: str) -> None:
    assert(opt.opt_type != 'version'), 'a single VersionCheck is useless'
    if opt.opt_type != 'complex':
        assert(isinstance(opt, SimpleOptCheckTypes)), \
               f'unexpected object {opt} with opt_type "{opt.opt_type}"'
        populate_simple_opt_with_data(opt, data, data_type)
    else:
        assert(isinstance(opt, ComplexOptCheckTypes)), \
               f'unexpected object {opt} with opt_type "{opt.opt_type}"'
        for o in opt.opts:
            if o.opt_type != 'complex':
                assert(isinstance(o, SimpleOptCheckTypes)), \
                       f'unexpected object {o} with opt_type "{o.opt_type}"'
                populate_simple_opt_with_data(o, data, data_type)
            else:
                # Recursion for nested ComplexOptCheck objects
                populate_opt_with_data(o, data, data_type)


def populate_with_data(checklist: List[ChecklistObjType], data: DictOrTuple, data_type: str) -> None:
    for opt in checklist:
        populate_opt_with_data(opt, data, data_type)


def override_expected_value(checklist: List[ChecklistObjType], name: str, new_val: str) -> None:
    for opt in checklist:
        if opt.name == name:
            assert(isinstance(opt, SimpleNamedOptCheckTypes)), \
                   f'overriding an expected value for "{opt}" is not supported yet'
            opt.expected = new_val


def perform_checks(checklist: List[ChecklistObjType]) -> None:
    for opt in checklist:
        opt.check()


def print_unknown_options(checklist: List[ChecklistObjType], parsed_options: Dict[str, str], opt_type: str) -> None:
    known_options = []

    for o1 in checklist:
        if isinstance(o1, SimpleOptCheckTypes):
            assert(o1.opt_type != 'complex'), f'{o1} with complex opt_type'
            assert(not isinstance(o1, VersionCheck)), 'single VersionCheck in checklist'
            known_options.append(o1.name)
            continue
        for o2 in o1.opts:
            if isinstance(o2, SimpleOptCheckTypes):
                assert(o2.opt_type != 'complex'), f'{o2} with complex opt_type'
                if hasattr(o2, 'name'):
                    known_options.append(o2.name)
                continue
            for o3 in o2.opts:
                assert(isinstance(o3, SimpleOptCheckTypes)), \
                       f'unexpected ComplexOptCheck inside {o2.name}'
                assert(o3.opt_type != 'complex'), f'{o3} with complex opt_type'
                if hasattr(o3, 'name'):
                    known_options.append(o3.name)

    for option, value in parsed_options.items():
        if option not in known_options:
            print(f'[?] No check for {opt_type} option {option} ({value})')
