import re
from collections import OrderedDict


class UserConfig:
    def __init__(self, fname):
        with open(fname, 'r') as f:
            self.options = OrderedDict()
            opt_is_on = re.compile("CONFIG_[a-zA-Z0-9_]*=[a-zA-Z0-9_\"]*")
            opt_is_off = re.compile("# CONFIG_[a-zA-Z0-9_]* is not set")

            print('[+] Checking "{}" against hardening preferences...'.format(fname))
            for line in f.readlines():
                line = line.strip()
                option = None
                value = None

                if opt_is_on.match(line):
                    option, value = line[7:].split('=', 1)
                elif opt_is_off.match(line):
                    option, value = line[9:].split(' ', 1)
                    if value != 'is not set':
                        sys.exit('[!] ERROR: bad disabled config option "{}"'.format(line))

                if option in self.options:
                    sys.exit('[!] ERROR: config option "{}" exists multiple times'.format(line))

                if option is not None:
                    self.options[option] = value

    def get_option(self, name):
        return self.options.get(name, None)
