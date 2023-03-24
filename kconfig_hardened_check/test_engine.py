#!/usr/bin/python3

"""
This tool helps me to check Linux kernel options against
my security hardening preferences for X86_64, ARM64, X86_32, and ARM.
Let the computers do their job!

Author: Alexander Popov <alex.popov@linux.com>

This module performs unit-testing of the kconfig-hardened-check engine.
"""

# pylint: disable=missing-function-docstring,line-too-long

import unittest
from collections import OrderedDict
import json
from .engine import KconfigCheck, CmdlineCheck, populate_with_data, perform_checks


class TestEngine(unittest.TestCase):
    """
    Example test scenario:

        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'KCONFIG_NAME', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'cmdline_name', 'expected_2')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_KCONFIG_NAME'] = 'UNexpected_1'

        # 3. prepare the parsed cmdline options
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['cmdline_name'] = 'expected_2'

        # 4. prepare the kernel version
        kernel_version = (42, 43)

        # 5. run the engine
        result = []
        self.run_engine(config_checklist,
                        parsed_kconfig_options, parsed_cmdline_options, kernel_version,
                        result)

        # 6. check that the results are correct
        # self.assertEqual(...
    """

    @staticmethod
    def run_engine(checklist,
                   parsed_kconfig_options, parsed_cmdline_options, kernel_version,
                   result):
        # populate the checklist with data
        populate_with_data(checklist, parsed_kconfig_options, 'kconfig')
        populate_with_data(checklist, parsed_cmdline_options, 'cmdline')
        populate_with_data(checklist, kernel_version, 'version')

        # now everything is ready, perform the checks
        perform_checks(checklist)

        # print the table with the results
        print('TABLE:')
        for opt in checklist:
            opt.table_print(None, True) # default mode, with_results
            print()

        # print the results in JSON
        print('JSON:')
        for opt in checklist:
            result.append(opt.json_dump(True)) # with_results
        print(json.dumps(result))
        print()

    def test_kconfig_ok(self):
        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'NAME_1', 'expected_1')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_1'] = 'expected_1'

        # 3. run the engine
        result = []
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, result)

        # 4. check that the results are correct
        self.assertEqual(
                result,
                [["CONFIG_NAME_1", "kconfig", "expected_1", "decision_1", "reason_1", "OK"]]
        )

    def test_kconfig_fail(self):
        # 1. prepare the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_2', 'decision_2', 'NAME_2', 'expected_2')]

        # 2. prepare the parsed kconfig options
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_NAME_2'] = 'UNexpected_2'

        # 3. run the engine
        result = []
        self.run_engine(config_checklist, parsed_kconfig_options, None, None, result)

        # 4. check that the results are correct
        self.assertEqual(
                result,
                [["CONFIG_NAME_2", "kconfig", "expected_2", "decision_2", "reason_2", "FAIL: \"UNexpected_2\""]]
        )
