from kconfig_hardened_check import main2
from . import list_configs, Args, cd_dir


def test_configs(capsys):
    for path1, path2 in list_configs():
        capsys.readouterr()
        with cd_dir(path1.resolve().parents[0]):
            args = Args(path1.name)
            main2(args)
        captured = capsys.readouterr()
        str1 = captured.out
        str2 = path2.read_text()
        assert str1 == str2
