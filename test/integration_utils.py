import json
import os
import pathlib
import re
import sys

import pytest

from gatox.main import entry


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


def process_command(commandline: str, capsys):
    """Utility method to handle passing command line to the gato
    main function.

    Args:
        commandline (str): Commandline arguments.
        capsys: Capture object for the test.

    Returns:
        tuple: tuple of standard output and error for the execution.
    """

    command = commandline.split(" ")

    sys.argv = command
    with pytest.raises(SystemExit):
        entry()

    output, error = capsys.readouterr()

    output = escape_ansi(output)
    error = escape_ansi(error)

    return output, error


def load_creds():
    curr_path = pathlib.Path(__file__).parent.resolve()

    with open(os.path.join(curr_path, "creds.json")) as f:
        creds = json.load(f)
    for key, val in creds.items():
        val["PAT_value"] = os.environ.get(key)

        if val["PAT_value"] is None:
            pytest.fail(f"Unable to load secret: {key}!")

    return creds
