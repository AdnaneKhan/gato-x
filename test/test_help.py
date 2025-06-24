from .integration_utils import process_command


def test_help(capsys):
    output, error = process_command("gato enum -h", capsys)

    assert " gato enumerate [-h] [--target ORGANIZATION]" in output
