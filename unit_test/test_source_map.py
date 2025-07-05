import yaml
from gatox.workflow_parser.source_map import (
    build_workflow_source_map,
    build_composite_source_map,
)


def test_build_workflow_source_map_with_jobs_and_steps():
    workflow_yaml = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: pytest
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
"""
    node = yaml.compose(workflow_yaml)
    result = build_workflow_source_map(node)

    assert result["jobs"]["test"]["line"] == 5
    assert result["jobs"]["build"]["line"] == 11
    assert result["jobs"]["test"]["steps"][0] == 8
    assert result["jobs"]["test"]["steps"][1] == 9
    assert result["jobs"]["build"]["steps"][0] == 14


def test_build_composite_source_map():
    composite_yaml = """
name: My Composite Action
description: A test composite action
runs:
  using: composite
  steps:
    - run: echo "Step 1"
    - run: echo "Step 2"
"""
    node = yaml.compose(composite_yaml)
    result = build_composite_source_map(node)

    assert result["steps"][0] == 7
    assert result["steps"][1] == 8
