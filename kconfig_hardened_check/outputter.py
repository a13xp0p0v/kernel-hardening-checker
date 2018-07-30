class Outputter:
    @staticmethod
    def print_opt_checks(checklist):
        print('[+] Printing kernel hardening preferences...')
        print('  {:<39}|{:^13}|{:^10}|{:^20}'.format(
            'option name', 'desired val', 'decision', 'reason')
        )
        print('  ' + '=' * 88)
        for opt in checklist:
            print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}'.format(
                opt.name, opt.expected, opt.decision, opt.reason)
            )
        print()

    @staticmethod
    def print_check_results(checklist):
        print('  {:<39}|{:^13}|{:^10}|{:^20}||{:^28}'.format(
            'option name', 'desired val', 'decision', 'reason', 'check result')
        )
        print('  ' + '=' * 117)
        for opt in checklist:
            print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}||{:^28}'.format(
                opt.name, opt.expected, opt.decision, opt.reason, opt.result)
            )
        print()

    @staticmethod
    def great_config():
        print('[+] config check is PASSED')

    @staticmethod
    def display_errors_count(error_count):
        print('[-] config check is NOT PASSED: {} errors'.format(error_count))
