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

from kconfig_hardened_check.checklist import Checklist
from kconfig_hardened_check.outputter import Outputter
from kconfig_hardened_check.userconfig import UserConfig


if __name__ == '__main__':
    parser = ArgumentParser(description='Checks the hardening options in the Linux kernel config')
    parser.add_argument('-p', '--print', action='store_true', help='print hardening preferences')
    parser.add_argument('-c', '--config', help='check the config_file against these preferences')
    parser.add_argument('--debug', default=False, action='store_true', help='enable internal debug mode')
    args = parser.parse_args()

    checklist = Checklist(debug=args.debug)

    if args.print:
        Outputter.print_opt_checks(checklist)
        sys.exit(0)

    if args.config:
        config = UserConfig(args.config)
        checklist.check(config)
        Outputter.print_check_results(checklist)

        error_count = checklist.get_errors_count()
        if error_count == 0:
            Outputter.great_config()
            sys.exit(0)
        else:
            Outputter.display_errors_count(error_count)
            sys.exit(1)

    parser.print_help()
