from .integration_utils import process_command


def test_help(capsys):
    output, error = process_command("gato-x enum -h", capsys)

    assert " gato-x enumerate [-h] [--target ORGANIZATION]" in output
