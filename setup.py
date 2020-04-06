#!/usr/bin/python3

from setuptools import setup

about = {}
with open("kconfig_hardened_check/__about__.py") as f:
    exec(f.read(), about)

print('v: "{}"'.format(about['__version__']))

# See the options in setup.cfg
setup(version = about['__version__'])
