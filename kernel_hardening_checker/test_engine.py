#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

Author: Alexander Popov <alex.popov@linux.com>

This module performs unit-testing of the kernel-hardening-checker engine.
"""

# pylint: disable=missing-function-docstring,line-too-long

import unittest
import io
import sys
from collections import OrderedDict
import json
import inspect
from .engine import KconfigCheck, CmdlineCheck, SysctlCheck, VersionCheck, OR, AND, populate_with_data, perform_checks, override_expected_value


class TestEngine(unittest.TestCase):
    """
    Example test scenario:

        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'KCONFIG_NAME', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'cmdline_name', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'sysctl_name', 'expected_3')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_KCONFIG_NAME'] = 'UNexpected_1'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['cmdline_name'] = 'expected_2'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options = OrderedDict()
        parsed_sysctl_options['sysctl_name'] = 'expected_3'

        # 5. prepare the kernel version
        kernel_version = (42, 43)

        # 6. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, kernel_version)

        # 7. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(...
    """

    @staticmethod
    def run_engine(checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, kernel_version):
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

        # print the table with the results
        print(f'\n{inspect.stack()[1].function}():')
        print('=' * 121)
        for opt in checklist:
            opt.table_print('verbose', True) # verbose mode, with_results
            print()
            print('=' * 121)

        # print the results in JSON
        result = []
        for opt in checklist:
            result.append(opt.json_dump(True)) # with_results
        print(json.dumps(result))
        print()

    @staticmethod
    def get_engine_result(checklist, result, result_type):
        assert(result_type in ('json', 'stdout', 'stdout_verbose')), \
               f'invalid result type "{result_type}"'

        if result_type == 'json':
            for opt in checklist:
                result.append(opt.json_dump(True)) # with_results
            return

        captured_output = io.StringIO()
        stdout_backup = sys.stdout
        sys.stdout = captured_output
        for opt in checklist:
            if result_type == 'stdout_verbose':
                opt.table_print('verbose', True) # verbose mode, with_results
            else:
                opt.table_print(None, True) # normal mode, with_results
        sys.stdout = stdout_backup
        result.append(captured_output.getvalue())

    def test_simple_kconfig(self):
        # 1. prepare the checklist
        config_checklist = []
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

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_7'] = 'really_not_off'
        parsed_kconfig_options['CONFIG_NAME_8'] = 'off'
        parsed_kconfig_options['CONFIG_NAME_9'] = '0'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['CONFIG_NAME_2', 'kconfig', 'expected_2', 'decision_2', 'reason_2', 'FAIL: "UNexpected_2"'],
                 ['CONFIG_NAME_3', 'kconfig', 'expected_3', 'decision_3', 'reason_3', 'FAIL: is not found'],
                 ['CONFIG_NAME_4', 'kconfig', 'is not set', 'decision_4', 'reason_4', 'OK: is not found'],
                 ['CONFIG_NAME_5', 'kconfig', 'is present', 'decision_5', 'reason_5', 'OK: is present'],
                 ['CONFIG_NAME_6', 'kconfig', 'is present', 'decision_6', 'reason_6', 'FAIL: is not present'],
                 ['CONFIG_NAME_7', 'kconfig', 'is not off', 'decision_7', 'reason_7', 'OK: is not off, "really_not_off"'],
                 ['CONFIG_NAME_8', 'kconfig', 'is not off', 'decision_8', 'reason_8', 'FAIL: is off'],
                 ['CONFIG_NAME_9', 'kconfig', 'is not off', 'decision_9', 'reason_9', 'FAIL: is off, "0"'],
                 ['CONFIG_NAME_10', 'kconfig', 'is not off', 'decision_10', 'reason_10', 'FAIL: is off, not found']]
        )

    def test_simple_cmdline(self):
        # 1. prepare the checklist
        config_checklist = []
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
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['name_1'] = 'expected_1'
        parsed_cmdline_options['name_2'] = 'UNexpected_2'
        parsed_cmdline_options['name_5'] = ''
        parsed_cmdline_options['name_7'] = ''
        parsed_cmdline_options['name_8'] = 'off'
        parsed_cmdline_options['name_9'] = '0'

        # 3. run the engine
        self.run_engine(config_checklist, None, parsed_cmdline_options, None, None)

        # 4. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['name_1', 'cmdline', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['name_2', 'cmdline', 'expected_2', 'decision_2', 'reason_2', 'FAIL: "UNexpected_2"'],
                 ['name_3', 'cmdline', 'expected_3', 'decision_3', 'reason_3', 'FAIL: is not found'],
                 ['name_4', 'cmdline', 'is not set', 'decision_4', 'reason_4', 'OK: is not found'],
                 ['name_5', 'cmdline', 'is present', 'decision_5', 'reason_5', 'OK: is present'],
                 ['name_6', 'cmdline', 'is present', 'decision_6', 'reason_6', 'FAIL: is not present'],
                 ['name_7', 'cmdline', 'is not off', 'decision_7', 'reason_7', 'OK: is not off, ""'],
                 ['name_8', 'cmdline', 'is not off', 'decision_8', 'reason_8', 'FAIL: is off'],
                 ['name_9', 'cmdline', 'is not off', 'decision_9', 'reason_9', 'FAIL: is off, "0"'],
                 ['name_10', 'cmdline', 'is not off', 'decision_10', 'reason_10', 'FAIL: is off, not found']]
        )

    def test_simple_sysctl(self):
        # 1. prepare the checklist
        config_checklist = []
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
        parsed_sysctl_options = OrderedDict()
        parsed_sysctl_options['name_1'] = 'expected_1'
        parsed_sysctl_options['name_2'] = 'UNexpected_2'
        parsed_sysctl_options['name_5'] = ''
        parsed_sysctl_options['name_7'] = ''
        parsed_sysctl_options['name_8'] = 'off'
        parsed_sysctl_options['name_9'] = '0'

        # 3. run the engine
        self.run_engine(config_checklist, None, None, parsed_sysctl_options, None)

        # 4. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['name_1', 'sysctl', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['name_2', 'sysctl', 'expected_2', 'decision_2', 'reason_2', 'FAIL: "UNexpected_2"'],
                 ['name_3', 'sysctl', 'expected_3', 'decision_3', 'reason_3', 'FAIL: is not found'],
                 ['name_4', 'sysctl', 'is not set', 'decision_4', 'reason_4', 'OK: is not found'],
                 ['name_5', 'sysctl', 'is present', 'decision_5', 'reason_5', 'OK: is present'],
                 ['name_6', 'sysctl', 'is present', 'decision_6', 'reason_6', 'FAIL: is not present'],
                 ['name_7', 'sysctl', 'is not off', 'decision_7', 'reason_7', 'OK: is not off, ""'],
                 ['name_8', 'sysctl', 'is not off', 'decision_8', 'reason_8', 'FAIL: is off'],
                 ['name_9', 'sysctl', 'is not off', 'decision_9', 'reason_9', 'FAIL: is off, "0"'],
                 ['name_10', 'sysctl', 'is not off', 'decision_10', 'reason_10', 'FAIL: is off, not found']]
        )

    def test_complex_or(self):
        # 1. prepare the checklist
        config_checklist = []
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

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'UNexpected_3'
        parsed_kconfig_options['CONFIG_NAME_4'] = 'expected_4'
        parsed_kconfig_options['CONFIG_NAME_5'] = 'UNexpected_5'
        parsed_kconfig_options['CONFIG_NAME_6'] = 'UNexpected_6'
        parsed_kconfig_options['CONFIG_NAME_10'] = 'UNexpected_10'
        parsed_kconfig_options['CONFIG_NAME_12'] = 'really_not_off'

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['CONFIG_NAME_3', 'kconfig', 'expected_3', 'decision_3', 'reason_3', 'OK: CONFIG_NAME_4 is "expected_4"'],
                 ['CONFIG_NAME_5', 'kconfig', 'expected_5', 'decision_5', 'reason_5', 'FAIL: "UNexpected_5"'],
                 ['CONFIG_NAME_7', 'kconfig', 'expected_7', 'decision_7', 'reason_7', 'OK: CONFIG_NAME_8 is not found'],
                 ['CONFIG_NAME_9', 'kconfig', 'expected_9', 'decision_9', 'reason_9', 'OK: CONFIG_NAME_10 is present'],
                 ['CONFIG_NAME_11', 'kconfig', 'expected_11', 'decision_11', 'reason_11', 'OK: CONFIG_NAME_12 is not off']]
        )

    def test_complex_and(self):
        # 1. prepare the checklist
        config_checklist = []
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

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
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

        # 3. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, None)

        # 4. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['CONFIG_NAME_3', 'kconfig', 'expected_3', 'decision_3', 'reason_3', 'FAIL: CONFIG_NAME_4 is not "expected_4"'],
                 ['CONFIG_NAME_5', 'kconfig', 'expected_5', 'decision_5', 'reason_5', 'FAIL: "UNexpected_5"'],
                 ['CONFIG_NAME_7', 'kconfig', 'expected_7', 'decision_7', 'reason_7', 'FAIL: CONFIG_NAME_8 is not present'],
                 ['CONFIG_NAME_9', 'kconfig', 'expected_9', 'decision_9', 'reason_9', 'FAIL: CONFIG_NAME_10 is off'],
                 ['CONFIG_NAME_11', 'kconfig', 'expected_11', 'decision_11', 'reason_11', 'FAIL: CONFIG_NAME_12 is off, not found']]
        )

    def test_complex_nested(self):
        # 1. prepare the checklist
        config_checklist = []
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
        parsed_kconfig_options = OrderedDict()
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
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK'],
                 ['CONFIG_NAME_4', 'kconfig', 'expected_4', 'decision_4', 'reason_4', 'FAIL: CONFIG_NAME_5 is not "expected_5"'],
                 ['CONFIG_NAME_7', 'kconfig', 'expected_7', 'decision_7', 'reason_7', 'OK: CONFIG_NAME_8 is "expected_8"'],
                 ['CONFIG_NAME_10', 'kconfig', 'expected_10', 'decision_10', 'reason_10', 'FAIL: "UNexpected_10"']]
        )

    def test_version(self):
        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                VersionCheck((41, 101)))]
        config_checklist += [AND(KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2'),
                                VersionCheck((44, 1)))]
        config_checklist += [AND(KconfigCheck('reason_3', 'decision_3', 'NAME_3', 'expected_3'),
                                VersionCheck((42, 44)))]
        config_checklist += [OR(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                VersionCheck((42, 43)))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_2'] = 'expected_2'
        parsed_kconfig_options['CONFIG_NAME_3'] = 'expected_3'

        # 3. prepare the kernel version
        kernel_version = (42, 43)

        # 4. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, kernel_version)

        # 5. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK: version >= 41.101'],
                 ['CONFIG_NAME_2', 'kconfig', 'expected_2', 'decision_2', 'reason_2', 'FAIL: version < 44.1'],
                 ['CONFIG_NAME_3', 'kconfig', 'expected_3', 'decision_3', 'reason_3', 'FAIL: version < 42.44'],
                 ['CONFIG_NAME_4', 'kconfig', 'expected_4', 'decision_4', 'reason_4', 'OK: version >= 42.43']]
        )

    def test_stdout(self):
        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [OR(KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1'),
                                CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2'),
                                SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3'))]
        config_checklist += [AND(KconfigCheck('reason_4', 'decision_4', 'NAME_4', 'expected_4'),
                                 CmdlineCheck('reason_5', 'decision_5', 'name_5', 'expected_5'),
                                 SysctlCheck('reason_6', 'decision_6', 'name_6', 'expected_6'))]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_1'] = 'UNexpected_1'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['name_2'] = 'expected_2'
        parsed_cmdline_options['name_5'] = 'UNexpected_5'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options = OrderedDict()
        parsed_sysctl_options['name_6'] = 'expected_6'

        # 5. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, None)

        # 6. check that the results are correct
        json_result = []
        self.get_engine_result(config_checklist, json_result, 'json')
        self.assertEqual(
                json_result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'OK: name_2 is "expected_2"'],
                 ['CONFIG_NAME_4', 'kconfig', 'expected_4', 'decision_4', 'reason_4', 'FAIL: name_5 is not "expected_5"']]
        )

        stdout_result = []
        self.get_engine_result(config_checklist, stdout_result, 'stdout')
        self.assertEqual(
                stdout_result,
                [
'\
CONFIG_NAME_1                           |kconfig| expected_1 |decision_1|     reason_1     | \x1b[32mOK: name_2 is "expected_2"\x1b[0m\
CONFIG_NAME_4                           |kconfig| expected_4 |decision_4|     reason_4     | \x1b[31mFAIL: name_5 is not "expected_5"\x1b[0m\
'               ]
        )

        stdout_result = []
        self.get_engine_result(config_checklist, stdout_result, 'stdout_verbose')
        self.assertEqual(
                stdout_result,
                [
'\
    <<< OR >>>                                                                             | \x1b[32mOK: name_2 is "expected_2"\x1b[0m\n\
CONFIG_NAME_1                           |kconfig| expected_1 |decision_1|     reason_1     | \x1b[31mFAIL: "UNexpected_1"\x1b[0m\n\
name_2                                  |cmdline| expected_2 |decision_2|     reason_2     | \x1b[32mOK\x1b[0m\n\
name_3                                  |sysctl | expected_3 |decision_3|     reason_3     | None\
'\
'\
    <<< AND >>>                                                                            | \x1b[31mFAIL: name_5 is not "expected_5"\x1b[0m\n\
CONFIG_NAME_4                           |kconfig| expected_4 |decision_4|     reason_4     | None\n\
name_5                                  |cmdline| expected_5 |decision_5|     reason_5     | \x1b[31mFAIL: "UNexpected_5"\x1b[0m\n\
name_6                                  |sysctl | expected_6 |decision_6|     reason_6     | \x1b[32mOK\x1b[0m\
'               ]
        )

    def test_value_overriding(self):
        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'name_2', 'expected_2')]
        config_checklist += [SysctlCheck('reason_3', 'decision_3', 'name_3', 'expected_3')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1_new'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['name_2'] = 'expected_2_new'

        # 4. prepare the parsed sysctl options
        parsed_sysctl_options = OrderedDict()
        parsed_sysctl_options['name_3'] = 'expected_3_new'

        # 5. run the engine
        self.run_engine(config_checklist, parsed_kconfig_options, parsed_cmdline_options, parsed_sysctl_options, None)

        # 6. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1', 'decision_1', 'reason_1', 'FAIL: "expected_1_new"'],
                 ['name_2', 'cmdline', 'expected_2', 'decision_2', 'reason_2', 'FAIL: "expected_2_new"'],
                 ['name_3', 'sysctl', 'expected_3', 'decision_3', 'reason_3', 'FAIL: "expected_3_new"']]
        )

        # 7. override expected value and perform the checks again
        override_expected_value(config_checklist, 'CONFIG_NAME_1', 'expected_1_new')
        perform_checks(config_checklist)

        # 8. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1_new', 'decision_1', 'reason_1', 'OK'],
                 ['name_2', 'cmdline', 'expected_2', 'decision_2', 'reason_2', 'FAIL: "expected_2_new"'],
                 ['name_3', 'sysctl', 'expected_3', 'decision_3', 'reason_3', 'FAIL: "expected_3_new"']]
        )

        # 9. override expected value and perform the checks again
        override_expected_value(config_checklist, 'name_2', 'expected_2_new')
        perform_checks(config_checklist)

        # 10. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1_new', 'decision_1', 'reason_1', 'OK'],
                 ['name_2', 'cmdline', 'expected_2_new', 'decision_2', 'reason_2', 'OK'],
                 ['name_3', 'sysctl', 'expected_3', 'decision_3', 'reason_3', 'FAIL: "expected_3_new"']]
        )

        # 11. override expected value and perform the checks again
        override_expected_value(config_checklist, 'name_3', 'expected_3_new')
        perform_checks(config_checklist)

        # 12. check that the results are correct
        result = []
        self.get_engine_result(config_checklist, result, 'json')
        self.assertEqual(
                result,
                [['CONFIG_NAME_1', 'kconfig', 'expected_1_new', 'decision_1', 'reason_1', 'OK'],
                 ['name_2', 'cmdline', 'expected_2_new', 'decision_2', 'reason_2', 'OK'],
                 ['name_3', 'sysctl', 'expected_3_new', 'decision_3', 'reason_3', 'OK']]
        )
