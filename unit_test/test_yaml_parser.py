from gatox.workflow_parser.yaml import parse_yaml, dump_yaml


def test_parse_yaml_with_tabs():
    yaml_str = """
    name: Test \t
    """
    parsed_yaml = parse_yaml(yaml_str)
    assert parsed_yaml["name"] == "Test"


def test_parse_yaml_with_on():
    yaml_str = """
    on:
      push:
        branches:
          - main
    """
    parsed_yaml = parse_yaml(yaml_str)
    assert parsed_yaml["on"]["push"]["branches"] == ["main"]


def test_dump_yaml():
    yaml_str = """
    name: Test
    """
    parsed_yaml = parse_yaml(yaml_str)
    assert parsed_yaml["name"] == "Test"

    dumped_yaml = dump_yaml(parsed_yaml)
    assert dumped_yaml == "name: Test"


def test_parse_yaml_line_numbers():
    yaml_str = """
    name: Test
    jobs:
      - name: Test
        runs-on: ubuntu-latest
        steps:
          - name: Run
            run: echo "Hello, world!"
    """
    parsed_yaml = parse_yaml(yaml_str)

    for job in parsed_yaml["jobs"]:
        assert job.lc.line == 3
        for step in job["steps"]:
            assert step.lc.line == 6
