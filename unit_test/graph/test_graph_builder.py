import pytest
from unittest.mock import AsyncMock, Mock, patch
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


@pytest.fixture
def builder():
    builder = WorkflowGraphBuilder()
    builder.graph = TaggedGraph(builder)
    return builder


@pytest.fixture
def mock_repo():
    repo = Mock(spec=Repository)
    repo.name = "test/repo"
    repo.description = "Test repo"
    return repo


@pytest.fixture
def mock_workflow():
    workflow = AsyncMock(spec=Workflow)
    workflow.repo_name = "test/repo"
    workflow.branch = "main"
    workflow.getPath.return_value = ".github/workflows/test.yml"
    workflow.isInvalid.return_value = False
    workflow.parsed_yml = {
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v2"}],
            }
        }
    }
    return workflow


@pytest.fixture
def mock_workflow2():
    workflow = AsyncMock(spec=Workflow)
    workflow.repo_name = "test/repo"
    workflow.branch = "main"
    workflow.getPath.return_value = ".github/workflows/test.yml"
    workflow.isInvalid.return_value = False
    workflow.parsed_yml = {
        "jobs": [
            {
                "name": "build",
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v2"}],
            }
        ]
    }
    return workflow


def test_singleton():
    builder1 = WorkflowGraphBuilder()
    builder2 = WorkflowGraphBuilder()
    assert builder1 is builder2


def test_build_lone_repo_graph(builder, mock_repo):
    builder.build_lone_repo_graph(mock_repo)
    assert len(builder.graph.nodes) == 1
    node = list(builder.graph.nodes)[0]
    assert node.name == "test/repo"


async def test_build_graph_from_yaml(builder, mock_workflow, mock_repo):
    await builder.build_graph_from_yaml(mock_workflow, mock_repo)
    assert len(builder.graph.nodes) > 0

    # Should have repo node
    repo_nodes = [n for n in builder.graph.nodes if "RepoNode" in n.get_tags()]
    assert len(repo_nodes) == 1

    # Should have workflow node
    wf_nodes = [n for n in builder.graph.nodes if "WorkflowNode" in n.get_tags()]
    assert len(wf_nodes) == 1


async def test_build_graph_from_yaml2(builder, mock_workflow2, mock_repo):
    await builder.build_graph_from_yaml(mock_workflow2, mock_repo)
    assert len(builder.graph.nodes) > 0

    # Should have repo node
    repo_nodes = [n for n in builder.graph.nodes if "RepoNode" in n.get_tags()]
    assert len(repo_nodes) == 1

    # Should have workflow node
    wf_nodes = [n for n in builder.graph.nodes if "WorkflowNode" in n.get_tags()]
    assert len(wf_nodes) == 1


async def test_build_graph_from_yaml_invalid(builder, mock_repo):
    workflow = Mock(spec=Workflow)
    workflow.repo_name = "test/repo"
    workflow.branch = "main"
    workflow.getPath.return_value = ".github/workflows/test.yml"
    workflow.isInvalid.return_value = False
    workflow.parsed_yml = {
        "jobs": [
            {
                "name_none": "build",
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v2"}],
            }
        ]
    }

    assert not await builder.build_graph_from_yaml(workflow, mock_repo)


async def test_build_workflow_jobs(builder, mock_workflow):
    wf_node = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
    await builder.build_workflow_jobs(mock_workflow, wf_node)

    # Should create job node
    job_nodes = [n for n in builder.graph.nodes if "JobNode" in n.get_tags()]
    assert len(job_nodes) == 1


async def test_invalid_workflow(builder, mock_workflow, mock_repo):
    mock_workflow.isInvalid.return_value = True
    await builder.build_graph_from_yaml(mock_workflow, mock_repo)
    assert len(builder.graph.nodes) == 0


@patch("gatox.workflow_graph.graph_builder.CacheManager")
async def test_initialize_action_node(mock_cache, builder):
    action_node = ActionNode(
        "actions/checkout@v2", "main", "workflow.yml", "test/repo", {}
    )
    api = Mock()
    api.retrieve_raw_action.return_value = """
    name: 'Test Action'
    runs:
      steps:
        - run: echo test
    """

    await builder._initialize_action_node(action_node, api)
    assert action_node.initialized
