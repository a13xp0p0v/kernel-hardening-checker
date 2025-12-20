#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
SPDX-License-Identifier: GPL-3.0-only

This module performs unit-testing of the kernel-hardening-checker engine.
"""

# pylint: disable=missing-function-docstring,line-too-long

import io
import sys
import unittest
from typing import Optional, Union
from unittest import mock

from .engine import (
    AND,
    OR,
    ChecklistObjType,
    CmdlineCheck,
    KconfigCheck,
    StrOrBool,
    SysctlCheck,
    VersionCheck,
    colorize_result,
    override_expected_value,
    perform_checks,
    populate_with_data,
    print_unknown_options,
)

ResultType = list[Union[dict[str, StrOrBool], str]]


class TestEngine(unittest.TestCase):
    """
    Example test scenario:

        # 1. prepare the checklist
        config_checklist = [] # type: list[ChecklistObjType]
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'KCONFIG_NAME', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'cmdline_name', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'sysctl_name', 'expected_3')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options  = {}
        parsed_kconfig_options['CONFIG_KCONFIG_NAME'] = 'UNexpected_1'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options  = {}
        parsed_cmdline_options['cmdline_name'] = 'expected_2'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options  = {}
        parsed_sysctl_options['sysctl_name'] = 'expected_3'

        # 5. prepare the kernel version
        kernel_version = (42, 43, 44)

        # 6. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, kernel_version)

        # 7. check that the results are correct
        result = [] # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(...
    """

    maxDiff = None

    @staticmethod
    def run_engine(checklist: list[ChecklistObjType],
                   parsed_kconfig_options: Optional[dict[str, str]],
                   parsed_cmdline_options: Optional[dict[str, str]],
                   parsed_sysctl_options: Optional[dict[str, str]],
                   kernel_version: Optional[tuple[int, int, int]]) -> None:
        # populate the checklist with data
        if parsed_kconfig_options:
            populate_with_data(checklist, parsed_kconfig_options, 'kconfig')
        if parsed_cmdline_options:
            populate_with_data(checklist, parsed_cmdline_options, 'cmdline')
        if parsed_sysctl_options:
            populate_with_data(checklist, parsed_sysctl_options, 'sysctl')
        if kernel_version:
            populate_with_data(checklist, kernel_version, 'version')

        # now everything is ready, perform the checks
        perform_checks(checklist)

    @staticmethod
    def get_engine_result(checklist: list[ChecklistObjType], result: ResultType, result_type: str) -> None:
        assert (result_type in {'json', 'stdout', 'stdout_verbose'}), \
               f'invalid result type "{result_type}"'

        if result_type == 'json':
            for opt in checklist:
                result.append(opt.json_dump(True))  # with_results
            return

        captured_output = io.StringIO()
        stdout_backup = sys.stdout
        sys.stdout = captured_output
        for opt in checklist:
            if result_type == 'stdout_verbose':
                opt.table_print('verbose', True)  # verbose mode, with_results
            else:
                opt.table_print(None, True)  # normal mode, with_results
        sys.stdout = stdout_backup
        result.append(captured_output.getvalue())

    @staticmethod
    def get_unknown_options(checklist: list[ChecklistObjType],
                            parsed_kconfig_options: Optional[dict[str, str]],
                            parsed_cmdline_options: Optional[dict[str, str]],
                            parsed_sysctl_options: Optional[dict[str, str]],
                            result: ResultType) -> None:
        captured_output = io.StringIO()
        stdout_backup = sys.stdout
        sys.stdout = captured_output
        if parsed_kconfig_options:
            print_unknown_options(checklist, parsed_kconfig_options, 'kconfig')
        if parsed_cmdline_options:
            print_unknown_options(checklist, parsed_cmdline_options, 'cmdline')
        if parsed_sysctl_options:
            print_unknown_options(checklist, parsed_sysctl_options, 'sysctl')
        sys.stdout = stdout_backup
        result.append(captured_output.getvalue())

    def test_simple_kconfig(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1')]
        config_checklist += [KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2')]
        config_checklist += [KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3')]
        config_checklist += [KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'is not set')]
        config_checklist += [KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'is present')]
        config_checklist += [KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'is present')]
        config_checklist += [KconfigCheck('reason_7', 'decision_7', 'NAME_7', 'is not off')]
        config_checklist += [KconfigCheck('reason_8', 'decision_8', 'NAME_8', 'is not off')]
        config_checklist += [KconfigCheck('reason_9', 'decision_9', 'NAME_9', 'is not off')]
        config_checklist += [KconfigCheck('reason_10', 'decision_10', 'NAME_10', 'is not off')]
        config_checklist += [KconfigCheck('reason_11', 'decision_11', 'NAME_11', '*expected_11*')]
        config_checklist += [KconfigCheck('reason_12', 'decision_12', 'NAME_12', '*expected_12*')]
        config_checklist += [KconfigCheck('reason_13', 'decision_13', 'NAME_13', '*expected_13*')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_7'] = 'really_not_off'
        parsed_kconfig_options['CONFIG_NAME_8'] = 'off'
        parsed_kconfig_options['CONFIG_NAME_9'] = '0'
        parsed_kconfig_options['CONFIG_NAME_11'] = '"expected_11,something,UNexpected2"'
        parsed_kconfig_options['CONFIG_NAME_12'] = 'UNexpected_12,something'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_2', 'type': 'kconfig', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: "UNexpected_2"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: is not found', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_4', 'type': 'kconfig', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'is not set', 'check_result': 'OK: is not found', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_5', 'type': 'kconfig', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'is present', 'check_result': 'OK: is present', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_6', 'type': 'kconfig', 'reason': 'reason_6', 'decision': 'decision_6', 'desired_val': 'is present', 'check_result': 'FAIL: is not present', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_7', 'type': 'kconfig', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'is not off', 'check_result': 'OK: is not off, "really_not_off"', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_8', 'type': 'kconfig', 'reason': 'reason_8', 'decision': 'decision_8', 'desired_val': 'is not off', 'check_result': 'FAIL: is off', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_9', 'type': 'kconfig', 'reason': 'reason_9', 'decision': 'decision_9', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, "0"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_10', 'type': 'kconfig', 'reason': 'reason_10', 'decision': 'decision_10', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, not found', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_11', 'type': 'kconfig', 'reason': 'reason_11', 'decision': 'decision_11', 'desired_val': '*expected_11*', 'check_result': 'OK: in "expected_11,something,UNexpected2"', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_12', 'type': 'kconfig', 'reason': 'reason_12', 'decision': 'decision_12', 'desired_val': '*expected_12*', 'check_result': 'FAIL: not in UNexpected_12,something', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_13', 'type': 'kconfig', 'reason': 'reason_13', 'decision': 'decision_13', 'desired_val': '*expected_13*', 'check_result': 'FAIL: is not found', 'check_result_bool': False}],
        )

    def test_simple_cmdline(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [CmdlineCheck('reason_1', 'decision_1', 'name_1', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2')]
        config_checklist += [CmdlineCheck('reason_3', 'decision_3', 'name_3', 'expected_3')]
        config_checklist += [CmdlineCheck('reason_4', 'decision_4', 'name_4', 'is not set')]
        config_checklist += [CmdlineCheck('reason_5', 'decision_5', 'name_5', 'is present')]
        config_checklist += [CmdlineCheck('reason_6', 'decision_6', 'name_6', 'is present')]
        config_checklist += [CmdlineCheck('reason_7', 'decision_7', 'name_7', 'is not off')]
        config_checklist += [CmdlineCheck('reason_8', 'decision_8', 'name_8', 'is not off')]
        config_checklist += [CmdlineCheck('reason_9', 'decision_9', 'name_9', 'is not off')]
        config_checklist += [CmdlineCheck('reason_10', 'decision_10', 'name_10', 'is not off')]

        # 2. prepare the parsed cmdline options
        parsed_cmdline_options = {}
        parsed_cmdline_options['name_1'] = 'expected_1'
        parsed_cmdline_options['name_2'] = 'UNexpected_2'
        parsed_cmdline_options['name_5'] = ''
        parsed_cmdline_options['name_7'] = ''
        parsed_cmdline_options['name_8'] = 'off'
        parsed_cmdline_options['name_9'] = '0'

        # 3. run the engine
        self.run_engine(config_checklist, None, parsed_cmdline_options, None, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'name_1', 'type': 'cmdline', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_2', 'type': 'cmdline', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: "UNexpected_2"', 'check_result_bool': False},
                 {'option_name': 'name_3', 'type': 'cmdline', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: is not found', 'check_result_bool': False},
                 {'option_name': 'name_4', 'type': 'cmdline', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'is not set', 'check_result': 'OK: is not found', 'check_result_bool': True},
                 {'option_name': 'name_5', 'type': 'cmdline', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'is present', 'check_result': 'OK: is present', 'check_result_bool': True},
                 {'option_name': 'name_6', 'type': 'cmdline', 'reason': 'reason_6', 'decision': 'decision_6', 'desired_val': 'is present', 'check_result': 'FAIL: is not present', 'check_result_bool': False},
                 {'option_name': 'name_7', 'type': 'cmdline', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'is not off', 'check_result': 'OK: is not off, ""', 'check_result_bool': True},
                 {'option_name': 'name_8', 'type': 'cmdline', 'reason': 'reason_8', 'decision': 'decision_8', 'desired_val': 'is not off', 'check_result': 'FAIL: is off', 'check_result_bool': False},
                 {'option_name': 'name_9', 'type': 'cmdline', 'reason': 'reason_9', 'decision': 'decision_9', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, "0"', 'check_result_bool': False},
                 {'option_name': 'name_10', 'type': 'cmdline', 'reason': 'reason_10', 'decision': 'decision_10', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, not found', 'check_result_bool': False}],
        )

    def test_simple_sysctl(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [SysctlCheck('reason_1', 'decision_1', 'name_1', 'expected_1')]
        config_checklist += [SysctlCheck('reason_2', 'decision_2', 'name_2', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3')]
        config_checklist += [SysctlCheck('reason_4', 'decision_4', 'name_4', 'is not set')]
        config_checklist += [SysctlCheck('reason_5', 'decision_5', 'name_5', 'is present')]
        config_checklist += [SysctlCheck('reason_6', 'decision_6', 'name_6', 'is present')]
        config_checklist += [SysctlCheck('reason_7', 'decision_7', 'name_7', 'is not off')]
        config_checklist += [SysctlCheck('reason_8', 'decision_8', 'name_8', 'is not off')]
        config_checklist += [SysctlCheck('reason_9', 'decision_9', 'name_9', 'is not off')]
        config_checklist += [SysctlCheck('reason_10', 'decision_10', 'name_10', 'is not off')]

        # 2. prepare the parsed sysctl options
        parsed_sysctl_options = {}
        parsed_sysctl_options['name_1'] = 'expected_1'
        parsed_sysctl_options['name_2'] = 'UNexpected_2'
        parsed_sysctl_options['name_5'] = ''
        parsed_sysctl_options['name_7'] = ''
        parsed_sysctl_options['name_8'] = 'off'
        parsed_sysctl_options['name_9'] = '0'

        # 3. run the engine
        self.run_engine(config_checklist, None, None, parsed_sysctl_options, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'name_1', 'type': 'sysctl', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_2', 'type': 'sysctl', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: "UNexpected_2"', 'check_result_bool': False},
                 {'option_name': 'name_3', 'type': 'sysctl', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: is not found', 'check_result_bool': False},
                 {'option_name': 'name_4', 'type': 'sysctl', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'is not set', 'check_result': 'OK: is not found', 'check_result_bool': True},
                 {'option_name': 'name_5', 'type': 'sysctl', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'is present', 'check_result': 'OK: is present', 'check_result_bool': True},
                 {'option_name': 'name_6', 'type': 'sysctl', 'reason': 'reason_6', 'decision': 'decision_6', 'desired_val': 'is present', 'check_result': 'FAIL: is not present', 'check_result_bool': False},
                 {'option_name': 'name_7', 'type': 'sysctl', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'is not off', 'check_result': 'OK: is not off, ""', 'check_result_bool': True},
                 {'option_name': 'name_8', 'type': 'sysctl', 'reason': 'reason_8', 'decision': 'decision_8', 'desired_val': 'is not off', 'check_result': 'FAIL: is off', 'check_result_bool': False},
                 {'option_name': 'name_9', 'type': 'sysctl', 'reason': 'reason_9', 'decision': 'decision_9', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, "0"', 'check_result_bool': False},
                 {'option_name': 'name_10', 'type': 'sysctl', 'reason': 'reason_10', 'decision': 'decision_10', 'desired_val': 'is not off', 'check_result': 'FAIL: is off, not found', 'check_result_bool': False}],
        )

    def test_complex_or(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'))]
        config_checklist += [OR(KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3'),
                                KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'))]
        config_checklist += [OR(KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'expected_5'),
                                KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'expected_6'))]
        config_checklist += [OR(KconfigCheck('reason_7', 'decision_7', 'NAME_7', 'expected_7'),
                                KconfigCheck('reason_8', 'decision_8', 'NAME_8', 'is not set'))]
        config_checklist += [OR(KconfigCheck('reason_9', 'decision_9', 'NAME_9', 'expected_9'),
                                KconfigCheck('reason_10', 'decision_10', 'NAME_10', 'is present'))]
        config_checklist += [OR(KconfigCheck('reason_11', 'decision_11', 'NAME_11', 'expected_11'),
                                KconfigCheck('reason_12', 'decision_12', 'NAME_12', 'is not off'))]
        config_checklist += [OR(KconfigCheck('reason_13', 'decision_13', 'NAME_13', 'expected_13'),
                                KconfigCheck('reason_14', 'decision_14', 'NAME_14', '*expected_14*'))]
        config_checklist += [OR(KconfigCheck('reason_15', 'decision_15', 'NAME_15', 'expected_15'),
                                KconfigCheck('reason_16', 'decision_16', 'NAME_16', '*expected_16*'))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'UNexpected_3'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'UNexpected_6'
        parsed_kconfig_options['CONFIG_NAME_10'] = 'UNexpected_10'
        parsed_kconfig_options['CONFIG_NAME_12'] = 'really_not_off'
        parsed_kconfig_options['CONFIG_NAME_13'] = 'UNexpected_13'
        parsed_kconfig_options['CONFIG_NAME_14'] = '"UNexpected_14,something,expected_14"'
        parsed_kconfig_options['CONFIG_NAME_15'] = 'UNexpected_15'
        parsed_kconfig_options['CONFIG_NAME_16'] = 'UNexpected_16,something,expected_16'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'OK: CONFIG_NAME_4 is "expected_4"', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_5', 'type': 'kconfig', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'expected_5', 'check_result': 'FAIL: "UNexpected_5"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_7', 'type': 'kconfig', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'expected_7', 'check_result': 'OK: CONFIG_NAME_8 is not found', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_9', 'type': 'kconfig', 'reason': 'reason_9', 'decision': 'decision_9', 'desired_val': 'expected_9', 'check_result': 'OK: CONFIG_NAME_10 is present', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_11', 'type': 'kconfig', 'reason': 'reason_11', 'decision': 'decision_11', 'desired_val': 'expected_11', 'check_result': 'OK: CONFIG_NAME_12 is not off', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_13', 'type': 'kconfig', 'reason': 'reason_13', 'decision': 'decision_13', 'desired_val': 'expected_13', 'check_result': 'OK: "expected_14" is in CONFIG_NAME_14', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_15', 'type': 'kconfig', 'reason': 'reason_15', 'decision': 'decision_15', 'desired_val': 'expected_15', 'check_result': 'OK: "expected_16" is in CONFIG_NAME_16', 'check_result_bool': True}],
        )

    def test_complex_and(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [AND(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                 KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'))]
        config_checklist += [AND(KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3'),
                                 KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'))]
        config_checklist += [AND(KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'expected_5'),
                                 KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'expected_6'))]
        config_checklist += [AND(KconfigCheck('reason_7', 'decision_7', 'NAME_7', 'expected_7'),
                                 KconfigCheck('reason_8', 'decision_8', 'NAME_8', 'is present'))]
        config_checklist += [AND(KconfigCheck('reason_9', 'decision_9', 'NAME_9', 'expected_9'),
                                 KconfigCheck('reason_10', 'decision_10', 'NAME_10', 'is not off'))]
        config_checklist += [AND(KconfigCheck('reason_11', 'decision_11', 'NAME_11', 'expected_11'),
                                 KconfigCheck('reason_12', 'decision_12', 'NAME_12', 'is not off'))]
        config_checklist += [AND(KconfigCheck('reason_13', 'decision_13', 'NAME_13', 'expected_13'),
                                 KconfigCheck('reason_14', 'decision_14', 'NAME_14', '*expected_14*'))]
        config_checklist += [AND(KconfigCheck('reason_15', 'decision_15', 'NAME_15', 'expected_15'),
                                 KconfigCheck('reason_16', 'decision_16', 'NAME_16', '*expected_16*'))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'expected_3'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'UNexpected_4'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'expected_6'
        parsed_kconfig_options['CONFIG_NAME_7'] = 'expected_7'
        parsed_kconfig_options['CONFIG_NAME_9'] = 'expected_9'
        parsed_kconfig_options['CONFIG_NAME_10'] = '0'
        parsed_kconfig_options['CONFIG_NAME_11'] = 'expected_11'
        parsed_kconfig_options['CONFIG_NAME_13'] = 'expected_13'
        parsed_kconfig_options['CONFIG_NAME_14'] = '"UNexpected_14,something"'
        parsed_kconfig_options['CONFIG_NAME_15'] = 'expected_15'
        parsed_kconfig_options['CONFIG_NAME_16'] = 'UNexpected_16,something'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: CONFIG_NAME_4 is not "expected_4"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_5', 'type': 'kconfig', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'expected_5', 'check_result': 'FAIL: "UNexpected_5"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_7', 'type': 'kconfig', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'expected_7', 'check_result': 'FAIL: CONFIG_NAME_8 is not present', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_9', 'type': 'kconfig', 'reason': 'reason_9', 'decision': 'decision_9', 'desired_val': 'expected_9', 'check_result': 'FAIL: CONFIG_NAME_10 is off', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_11', 'type': 'kconfig', 'reason': 'reason_11', 'decision': 'decision_11', 'desired_val': 'expected_11', 'check_result': 'FAIL: CONFIG_NAME_12 is off, not found', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_13', 'type': 'kconfig', 'reason': 'reason_13', 'decision': 'decision_13', 'desired_val': 'expected_13', 'check_result': 'FAIL: "expected_14" is not in CONFIG_NAME_14', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_15', 'type': 'kconfig', 'reason': 'reason_15', 'decision': 'decision_15', 'desired_val': 'expected_15', 'check_result': 'FAIL: "expected_16" is not in CONFIG_NAME_16', 'check_result_bool': False}],
        )

    def test_complex_nested(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [AND(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                 OR(KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'),
                                    KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3')))]
        config_checklist += [AND(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                 OR(KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'expected_5'),
                                    KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'expected_6')))]
        config_checklist += [OR(KconfigCheck('reason_7', 'decision_7', 'NAME_7', 'expected_7'),
                                 AND(KconfigCheck('reason_8', 'decision_8', 'NAME_8', 'expected_8'),
                                     KconfigCheck('reason_9', 'decision_9', 'NAME_9', 'expected_9')))]
        config_checklist += [OR(KconfigCheck('reason_10', 'decision_10', 'NAME_10', 'expected_10'),
                                 AND(KconfigCheck('reason_11', 'decision_11', 'NAME_11', 'expected_11'),
                                     KconfigCheck('reason_12', 'decision_12', 'NAME_12', 'expected_12')))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'expected_3'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'UNexpected_6'
        parsed_kconfig_options['CONFIG_NAME_7'] = 'UNexpected_7'
        parsed_kconfig_options['CONFIG_NAME_8'] = 'expected_8'
        parsed_kconfig_options['CONFIG_NAME_9'] = 'expected_9'
        parsed_kconfig_options['CONFIG_NAME_10'] = 'UNexpected_10'
        parsed_kconfig_options['CONFIG_NAME_11'] = 'UNexpected_11'
        parsed_kconfig_options['CONFIG_NAME_12'] = 'expected_12'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_4', 'type': 'kconfig', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'expected_4', 'check_result': 'FAIL: CONFIG_NAME_5 is not "expected_5"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_7', 'type': 'kconfig', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'expected_7', 'check_result': 'OK: CONFIG_NAME_8 is "expected_8"', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_10', 'type': 'kconfig', 'reason': 'reason_10', 'decision': 'decision_10', 'desired_val': 'expected_10', 'check_result': 'FAIL: "UNexpected_10"', 'check_result_bool': False}],
        )

    def test_version(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                VersionCheck((41, 101, 0)))]
        config_checklist += [AND(KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'),
                                 VersionCheck((43, 1, 0)))]
        config_checklist += [OR(KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3'),
                                VersionCheck((42, 42, 101)))]
        config_checklist += [AND(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                 VersionCheck((42, 44, 1)))]
        config_checklist += [OR(KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'expected_5'),
                                VersionCheck((42, 43, 44)))]
        config_checklist += [AND(KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'expected_6'),
                                 VersionCheck((42, 43, 45)))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'expected_6'

        # 3. prepare the kernel version
        kernel_version = (42, 43, 44)

        # 4. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, kernel_version)

        # 5. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK: version >= (41, 101, 0)', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_2', 'type': 'kconfig', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: version < (43, 1, 0)', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'OK: version >= (42, 42, 101)', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_4', 'type': 'kconfig', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'expected_4', 'check_result': 'FAIL: version < (42, 44, 1)', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_5', 'type': 'kconfig', 'reason': 'reason_5', 'decision': 'decision_5', 'desired_val': 'expected_5', 'check_result': 'OK: version >= (42, 43, 44)', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_6', 'type': 'kconfig', 'reason': 'reason_6', 'decision': 'decision_6', 'desired_val': 'expected_6', 'check_result': 'FAIL: version < (42, 43, 45)', 'check_result_bool': False}],
        )

    def test_stdout(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2'),
                                SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3'))]
        config_checklist += [AND(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                 CmdlineCheck('reason_5', 'decision_5', 'name_5', 'expected_5'),
                                 SysctlCheck('reason_6', 'decision_6', 'name_6', 'expected_6'))]
        config_checklist += [AND(KconfigCheck('reason_7', 'decision_7', 'NAME_7', 'expected_7'),
                                 VersionCheck((42, 43, 44)))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'UNexpected_1'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = {}
        parsed_cmdline_options['name_2'] = 'expected_2'
        parsed_cmdline_options['name_5'] = 'UNexpected_5'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options = {}
        parsed_sysctl_options['name_6'] = 'expected_6'

        # 5. prepare the kernel version
        kernel_version = (42, 43, 43)

        # 6. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, kernel_version)

        # 7. check that the results are correct
        json_result = []  # type: ResultType
        self.get_engine_result(config_checklist, json_result, 'json')
        self.assertEqual(
                json_result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'OK: name_2 is "expected_2"', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_4', 'type': 'kconfig', 'reason': 'reason_4', 'decision': 'decision_4', 'desired_val': 'expected_4', 'check_result': 'FAIL: name_5 is not "expected_5"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_7', 'type': 'kconfig', 'reason': 'reason_7', 'decision': 'decision_7', 'desired_val': 'expected_7', 'check_result': 'FAIL: version < (42, 43, 44)', 'check_result_bool': False}],
        )

        stdout_result = []  # type: ResultType
        self.get_engine_result(config_checklist, stdout_result, 'stdout')
        self.assertEqual(
                stdout_result,
                ['\
CONFIG_NAME_1                         |kconfig|     reason_1     |decision_1| expected_1 | OK: name_2 is "expected_2"\
CONFIG_NAME_4                         |kconfig|     reason_4     |decision_4| expected_4 | FAIL: name_5 is not "expected_5"\
CONFIG_NAME_7                         |kconfig|     reason_7     |decision_7| expected_7 | FAIL: version < (42, 43, 44)'],
        )

        stdout_result = []
        self.get_engine_result(config_checklist, stdout_result, 'stdout_verbose')
        self.assertEqual(
                stdout_result,
                ['\
    <<< OR >>>                                                                           | OK: name_2 is "expected_2"\n\
CONFIG_NAME_1                         |kconfig|     reason_1     |decision_1| expected_1 | FAIL: "UNexpected_1"\n\
name_2                                |cmdline|     reason_2     |decision_2| expected_2 | OK\n\
name_3                                |sysctl |     reason_3     |decision_3| expected_3 | None\
    <<< AND >>>                                                                          | FAIL: name_5 is not "expected_5"\n\
CONFIG_NAME_4                         |kconfig|     reason_4     |decision_4| expected_4 | None\n\
name_5                                |cmdline|     reason_5     |decision_5| expected_5 | FAIL: "UNexpected_5"\n\
name_6                                |sysctl |     reason_6     |decision_6| expected_6 | OK\
    <<< AND >>>                                                                          | FAIL: version < (42, 43, 44)\n\
CONFIG_NAME_7                         |kconfig|     reason_7     |decision_7| expected_7 | None\n\
kernel version >= (42, 43, 44)                                                           | FAIL: version < (42, 43, 44)'],
        )

    def test_simple_value_overriding(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1_new'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = {}
        parsed_cmdline_options['name_2'] = 'expected_2_new'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options = {}
        parsed_sysctl_options['name_3'] = 'expected_3_new'

        # 5. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, None)

        # 6. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'FAIL: "expected_1_new"', 'check_result_bool': False},
                 {'option_name': 'name_2', 'type': 'cmdline', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: "expected_2_new"', 'check_result_bool': False},
                 {'option_name': 'name_3', 'type': 'sysctl', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: "expected_3_new"', 'check_result_bool': False}],
        )

        # 7. override expected value and perform the checks again
        override_expected_value(config_checklist, 'CONFIG_NAME_1', 'expected_1_new')
        perform_checks(config_checklist)

        # 8. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_2', 'type': 'cmdline', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2', 'check_result': 'FAIL: "expected_2_new"', 'check_result_bool': False},
                 {'option_name': 'name_3', 'type': 'sysctl', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: "expected_3_new"', 'check_result_bool': False}],
        )

        # 9. override expected value and perform the checks again
        override_expected_value(config_checklist, 'name_2', 'expected_2_new')
        perform_checks(config_checklist)

        # 10. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_2', 'type': 'cmdline', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_3', 'type': 'sysctl', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: "expected_3_new"', 'check_result_bool': False}],
        )

        # 11. override expected value and perform the checks again
        override_expected_value(config_checklist, 'name_3', 'expected_3_new')
        perform_checks(config_checklist)

        # 12. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_2', 'type': 'cmdline', 'reason': 'reason_2', 'decision': 'decision_2', 'desired_val': 'expected_2_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'name_3', 'type': 'sysctl', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3_new', 'check_result': 'OK', 'check_result_bool': True}],
        )

    def test_complex_value_overriding(self) -> None:
        # 1. prepare the checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'))]
        config_checklist += [AND(KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3'),
                                 KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'))]

        # 2. prepare the parsed kconfig OR options
        parsed_kconfig_options = {}
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1_new'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'

        # 3. prepare the parsed kconfig AND options
        parsed_kconfig_options['CONFIG_NAME_3'] = 'expected_3_new'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'

        # 4. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 5. check that the results are correct
        result = []  # type: ResultType
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1', 'check_result': 'FAIL: "expected_1_new"', 'check_result_bool': False},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3', 'check_result': 'FAIL: "expected_3_new"', 'check_result_bool': False}],
        )

        # 6. override expected value and perform the checks again
        override_expected_value(config_checklist, 'CONFIG_NAME_1', 'expected_1_new')
        override_expected_value(config_checklist, 'CONFIG_NAME_3', 'expected_3_new')
        perform_checks(config_checklist)

        # 7. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [{'option_name': 'CONFIG_NAME_1', 'type': 'kconfig', 'reason': 'reason_1', 'decision': 'decision_1', 'desired_val': 'expected_1_new', 'check_result': 'OK', 'check_result_bool': True},
                 {'option_name': 'CONFIG_NAME_3', 'type': 'kconfig', 'reason': 'reason_3', 'decision': 'decision_3', 'desired_val': 'expected_3_new', 'check_result': 'OK', 'check_result_bool': True}],
        )

    def test_print_unknown_options_simple(self) -> None:
        # 1. prepare simple checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3')]

        # 2. prepare parsed options
        parsed_kconfig_options = {}
        parsed_cmdline_options = {}
        parsed_sysctl_options = {}

        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_1'] = 'expected_1'

        parsed_cmdline_options['name_2'] = 'expected_2'
        parsed_cmdline_options['NOCHECK_name_2'] = 'expected_2'

        parsed_sysctl_options['name_3'] = 'expected_3'
        parsed_sysctl_options['NOCHECK_name_3'] = 'expected_3'

        # 3. run the print_unknown_options
        result = []  # type: ResultType
        self.get_unknown_options(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, result)

        # 4. check that the results are correct
        self.assertEqual(
            result,
            ['\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_1 (expected_1)\n\
[?] No check for cmdline option NOCHECK_name_2 (expected_2)\n\
[?] No check for sysctl option NOCHECK_name_3 (expected_3)\n'])

    def test_print_unknown_options_complex(self) -> None:
        # 1. prepare partially complex checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'))]
        config_checklist += [AND(CmdlineCheck('reason_3', 'decision_3', 'name_3', 'expected_3'),
                                 KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'))]
        config_checklist += [OR(SysctlCheck('reason_5', 'decision_5', 'name_5', 'expected_5'),
                                KconfigCheck('reason_6', 'decision_6', 'NAME_6', 'expected_6'))]

        # 2. prepare parsed options
        parsed_kconfig_options = {}
        parsed_cmdline_options = {}
        parsed_sysctl_options = {}

        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'expected_6'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_6'] = 'expected_6'

        parsed_cmdline_options['name_3'] = 'expected_3'
        parsed_cmdline_options['NOCHECK_name_3'] = 'expected_3'

        parsed_sysctl_options['name_5'] = 'expected_5'
        parsed_sysctl_options['NOCHECK_name_5'] = 'expected_5'

        # 3. run the print_unknown_options
        result = []  # type: ResultType
        self.get_unknown_options(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, result)

        # 4. check that the results are correct
        self.assertEqual(
            result,
            ['\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_1 (expected_1)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_2 (expected_2)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_4 (expected_4)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_6 (expected_6)\n\
[?] No check for cmdline option NOCHECK_name_3 (expected_3)\n\
[?] No check for sysctl option NOCHECK_name_5 (expected_5)\n'])

    def test_print_unknown_options_complex_nested(self) -> None:
        # 1. prepare partially complex checklist
        config_checklist = []  # type: list[ChecklistObjType]
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                AND(KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'),
                                    KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3')))]
        config_checklist += [OR(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                AND(KconfigCheck('reason_5', 'decision_5', 'NAME_5', 'expected_5'),
                                    VersionCheck((5, 9, 0))))]
        config_checklist += [OR(CmdlineCheck('reason_6', 'decision_6', 'name_6', 'expected_6'),
                                AND(SysctlCheck('reason_7', 'decision_7', 'name_7', 'expected_7'),
                                    KconfigCheck('reason_8', 'decision_8', 'NAME_8', 'expected_8')))]

        # 2. prepare parsed options
        parsed_kconfig_options = {}
        parsed_cmdline_options = {}
        parsed_sysctl_options = {}

        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'expected_3'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_3'] = 'expected_3'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'expected_5'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_5'] = 'expected_5'
        parsed_kconfig_options['CONFIG_NAME_8'] = 'expected_8'
        parsed_kconfig_options['CONFIG_NOCHECK_NAME_8'] = 'expected_8'

        parsed_cmdline_options['name_6'] = 'expected_6'
        parsed_cmdline_options['NOCHECK_name_6'] = 'expected_6'

        parsed_sysctl_options['name_7'] = 'expected_7'
        parsed_sysctl_options['NOCHECK_name_7'] = 'expected_7'

        # 3. run the print_unknown_options
        result = []  # type: ResultType
        self.get_unknown_options(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, result)

        # 4. check that the results are correct
        self.assertEqual(
            result,
            ['\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_1 (expected_1)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_2 (expected_2)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_3 (expected_3)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_4 (expected_4)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_5 (expected_5)\n\
[?] No check for kconfig option CONFIG_NOCHECK_NAME_8 (expected_8)\n\
[?] No check for cmdline option NOCHECK_name_6 (expected_6)\n\
[?] No check for sysctl option NOCHECK_name_7 (expected_7)\n'])

    def test_colorize_result(self) -> None:
        # 1. prepare the checklists
        with_color = ['\x1b[32mOK\x1b[0m']
        with_color += ['\x1b[31mFAIL: expected_1\x1b[0m']
        no_color = ['OK']
        no_color += ['FAIL: expected_1']

        # 2. run and check that results are correct with sys.stdout.isatty()=True
        with mock.patch('sys.stdout') as stdout:
            stdout.isatty.return_value = True
            self.assertEqual(with_color,
                             [colorize_result('OK'),
                              colorize_result('FAIL: expected_1')])

        # 3. run and check that results are correct with sys.stdout.isatty()=False
        with mock.patch('sys.stdout') as stdout:
            stdout.isatty.return_value = False
            self.assertEqual(None, colorize_result(None))
            self.assertEqual(no_color,
                             [colorize_result('OK'),
                              colorize_result('FAIL: expected_1')])
