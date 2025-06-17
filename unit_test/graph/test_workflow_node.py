import yaml
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.models.workflow import Workflow


def test_workflow_node_init():
    workflow_node = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
    workflow_node.initialize(
        Workflow(
            "test/repo",
            yaml.dump({"name": "Test Workflow"}),
            "test.yml",
        )
    )

    assert workflow_node.name == "test/repo:main:.github/workflows/test.yml"
    assert workflow_node.permissions == "default"


def test_workflow_node_init_permissions():
    workflow_node = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
    workflow_node.initialize(
        Workflow(
            "test/repo",
            yaml.dump({"name": "Test Workflow", "permissions": "read-all"}),
            "test.yml",
        )
    )

    assert workflow_node.name == "test/repo:main:.github/workflows/test.yml"
    assert workflow_node.permissions == "read-all"
