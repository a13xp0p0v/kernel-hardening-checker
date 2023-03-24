#!/usr/bin/python3

"""
This tool helps me to check Linux kernel options against
my security hardening preferences for X86_64, ARM64, X86_32, and ARM.
Let the computers do their job!

Author: Alexander Popov <alex.popov@linux.com>

This module performs unit-testing of the kconfig-hardened-check engine.
"""

import unittest
from collections import OrderedDict
import json
from .engine import KconfigCheck, CmdlineCheck, populate_with_data, perform_checks

class TestEngine(unittest.TestCase):
    def test_1(self):
        # add checks to the checklist
        config_checklist = []
        config_checklist += [KconfigCheck('reason_1', 'decision_1', 'KCONFIG_NAME', 'expected_1')]
        config_checklist += [CmdlineCheck('reason_2', 'decision_2', 'cmdline_name', 'expected_2')]

        # populate the checklist with the parsed kconfig data
        parsed_kconfig_options = OrderedDict()
        parsed_kconfig_options['CONFIG_KCONFIG_NAME'] = 'UNexpected_1'
        populate_with_data(config_checklist, parsed_kconfig_options, 'kconfig')

        # populate the checklist with the parsed cmdline data
        parsed_cmdline_options = OrderedDict()
        parsed_cmdline_options['cmdline_name'] = 'expected_2'
        populate_with_data(config_checklist, parsed_cmdline_options, 'cmdline')

        # populate the checklist with the kernel version data
        kernel_version = (42, 43)
        populate_with_data(config_checklist, kernel_version, 'version')

        # now everything is ready, perform the checks
        perform_checks(config_checklist)

        # print the results in json
        output = []
        print('JSON:')
        for opt in config_checklist:
            output.append(opt.json_dump(True))
        print(json.dumps(output))

        # print the results
        print('TABLE:')
        for opt in config_checklist:
            opt.table_print(None, True)
            print()
        print()

        self.assertEqual('foo'.upper(), 'FOO')

    def test_2(self):
        self.assertTrue('FOO'.isupper())
