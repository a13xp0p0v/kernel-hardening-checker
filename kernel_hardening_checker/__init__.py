#!/usr/bin/env python3

"""
This tool is for checking the security hardening options of the Linux kernel.

SPDX-FileCopyrightText: Alexander Popov <alex.popov@linux.com>
SPDX-License-Identifier: GPL-3.0-only
"""

from .cli import __version__, main

__all__ = [
    '__version__',
    'main',
]
