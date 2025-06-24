import os
import pytest
import pathlib
import json

from .integration_utils import process_command
from .integration_utils import load_creds


def load_cases():
    """Load test cases from the test case JSON file."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    with open(os.path.join(curr_path, "test_cases.json"), "r") as f:
        cases = json.load(f)

    creds = load_creds()

    parameters = []

    for case in cases:
        test_creds = creds[case["PAT"]]
        if test_creds["PAT_value"]:
            parameters.append((case, test_creds))

    return parameters


@pytest.mark.parametrize("test_details, test_creds", load_cases())
def test_gato(test_details, test_creds, capsys):
    if not test_creds["PAT_value"]:
        pytest.fail("The PAT was not set!!")

    os.environ["GH_TOKEN"] = test_creds["PAT_value"]

    output, error = process_command(test_details["invocation"], capsys)

    for assertion in test_details["assertions"]:
        print(output)

        if assertion["type"] == "stdout":
            assert assertion["expect"] in output
        else:
            assert assertion["expect"] in error

    if "extra_validation" in test_details:
        validation = test_details["extra_validation"]

        if validation["type"] == "file":
            with open(validation["filename"]) as file_check:
                file_contents = file_check.read()

                for assertion in validation["assertions"]:
                    assert assertion in file_contents
