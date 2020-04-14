import os
from contextlib import contextmanager
from pathlib import Path

SRC_PATH = Path('kconfig_hardened_check/config_files')
assert SRC_PATH.is_dir()

RESULT_PATH = Path('tests/results')
assert RESULT_PATH.is_dir()

def list_configs():
    for fpath1 in SRC_PATH.glob('**/*.config'):
        print(f'fpath1: {fpath1}')
        assert fpath1.is_file()
        relpath = fpath1.relative_to(SRC_PATH)
        fpath2 = RESULT_PATH / relpath
        fpath2 = fpath2.with_name(fpath2.name + '.check')
        print(f'fpath2: {fpath2}')
        assert fpath2.is_file()
        yield fpath1, fpath2


class Args:
    def __init__(self, config):
        self.config = config
        self.print = False
        self.json = False

        self.debug = False
        self.debug_mode = False
        # json_mode is for printing results in JSON format
        self.json_mode = False
        self.kernel_version = None


@contextmanager
def cd_dir(dir_):
    assert dir_.is_dir()
    pwd = Path('.').resolve()
    os.chdir(dir_)
    yield
    os.chdir(pwd)
