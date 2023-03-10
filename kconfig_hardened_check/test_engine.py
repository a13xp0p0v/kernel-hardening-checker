#!/usr/bin/python3

"""
This tool helps me to check Linux kernel options against
my security hardening preferences for X86_64, ARM64, X86_32, and ARM.
Let the computers do their job!

Author: Alexander Popov <alex.popov@linux.com>

This module performs unit-testing of the kconfig-hardened-check engine.
"""

import unittest
# from .engine import populate_with_data, perform_checks

class TestEngine(unittest.TestCase):
    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertTrue('Foo'.isupper())
