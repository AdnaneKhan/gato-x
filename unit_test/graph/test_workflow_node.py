import pytest
import yaml

from gatox.models.workflow import Workflow
from gatox.workflow_graph.nodes.workflow import WorkflowNode


def make_node(on: dict) -> WorkflowNode:
    yml = {"on": on, "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}}}
    workflow = Workflow("test/repo", yaml.dump(yml), "test.yml")
    node = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
    node.initialize(workflow)
    return node


@pytest.mark.parametrize(
    "on, expected",
    [
        ({"workflow_dispatch": {"inputs": {"name": {"type": "string"}}}}, True),
        ({"workflow_dispatch": None}, True),
        ({"workflow_run": {"workflows": ["CI"], "branches": ["main"]}}, True),
        (
            {
                "workflow_dispatch": {"inputs": {"name": {"type": "string"}}},
                "workflow_run": {"workflows": ["CI"], "types": ["completed"]},
            },
            False,
        ),
        (
            {
                "pull_request_target": None,
                "workflow_run": {"workflows": ["CI"], "branches": ["main"]},
            },
            False,
        ),
        ({"pull_request_target": None}, False),
    ],
)
def test_excluded_only_when_no_trigger_is_open(on, expected):
    assert make_node(on).excluded() is expected
