class OptCheck:
    def __init__(self, name, expected, decision, reason):
        self.name = name
        self.expected = expected
        self.decision = decision
        self.reason = reason
        self.state = None
        self.result = None

    def check(self):
        if self.expected == self.state:
            self.result = 'OK'
        elif self.state is None:
            if self.expected == 'is not set':
                self.result = 'OK: not found'
            else:
                self.result = 'FAIL: not found'
        else:
            self.result = 'FAIL: "' + self.state + '"'

        if self.result.startswith('OK'):
            return True, self.result
        else:
            return False, self.result

    def __repr__(self):
        return '{} = {}'.format(self.name, self.state)


class OR:
    def __init__(self, *opts):
        self.opts = opts
        self.result = None

    # self.opts[0] is the option which this OR-check is about.
    # Use case: OR(<X_is_hardened>, <X_is_disabled>)

    @property
    def name(self):
        return self.opts[0].name

    @property
    def expected(self):
        return self.opts[0].expected

    @property
    def state(self):
        return self.opts[0].state

    @property
    def decision(self):
        return self.opts[0].decision

    @property
    def reason(self):
        return self.opts[0].reason

    def check(self):
        for i, opt in enumerate(self.opts):
            result, msg = opt.check()
            if result:
                if i == 0:
                    self.result = opt.result
                else:
                    self.result = 'CONFIG_{}: {} ("{}")'.format(opt.name, opt.result, opt.expected)
                return True, self.result
        self.result = self.opts[0].result
        return False, self.result
