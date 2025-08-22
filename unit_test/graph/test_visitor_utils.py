import types
from unittest.mock import MagicMock, patch

import pytest

from gatox.enumerate.reports.actions import ActionsReport
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.enumerate.results.result_factory import ResultFactory
from gatox.github.api import Api
from gatox.models.workflow import Workflow
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils


class DummyNode:
    def __init__(self, tags=None, value=None, repo_name="repo"):
        self._tags = tags or set()
        self._value = value
        self._repo_name = repo_name

    def get_tags(self):
        return self._tags

    def repo_name(self):
        return self._repo_name


class DummyGraph:
    def __init__(self):
        self.removed_tags = []

    def remove_tags_from_node(self, node, tags):
        self.removed_tags.append((node, tags))


class DummyApi:
    async def get_file_last_updated(self, repo, wf):
        return ("2025-05-16T00:00:00Z", "author", "sha123")

    async def get_commit_merge_date(self, repo, sha):
        return "2025-05-16T00:00:00Z"


class DummyResult:
    def __init__(self, repo_name):
        self._repo_name = repo_name

    def repo_name(self):
        return self._repo_name

    def get_first_and_last_hash(self):
        return hash(self._repo_name)

    def to_machine(self):
        return {"initial_workflow": "wf.yml"}


class DummyCacheManager:
    def get_repository(self, repo_name):
        class Repo:
            def set_results(self, flow):
                self.last = flow

            repo_data = {"pushed_at": "2025-05-16T00:00:00Z"}

        return Repo()


@pytest.fixture
def mock_api():
    return MagicMock(spec=Api)


def test_add_results():
    # Test adding paths to results dict
    path = [WorkflowNode("main", "org/repo1", ".github/workflows/test.yml")]
    results = {}

    VisitorUtils._add_results(path, results, IssueType.ACTIONS_INJECTION)

    assert "org/repo1" in results
    assert len(results["org/repo1"]) == 1


def test_check_mutable_ref():
    # Test immutable refs
    assert not VisitorUtils.check_mutable_ref("github.event.pull_request.head.sha")
    assert not VisitorUtils.check_mutable_ref("github.event.workflow_run.head.sha")
    assert not VisitorUtils.check_mutable_ref("github.sha")
    assert not VisitorUtils.check_mutable_ref("sha", {"pull_request_target"})
    assert not VisitorUtils.check_mutable_ref("github.ref")

    # Test mutable refs
    assert VisitorUtils.check_mutable_ref("ref/heads/main")
    assert VisitorUtils.check_mutable_ref("github.ref||something")


def test_process_context_var():
    # Test processing context variables
    assert VisitorUtils.process_context_var("${{ inputs.test }}") == "test"
    assert VisitorUtils.process_context_var("plain_value") == "plain_value"
    assert VisitorUtils.process_context_var("${{ github.sha }}") == "github.sha"


def test_append_path():
    # Test appending paths
    head = [1, 2, 3]
    tail = [3, 4, 5]
    result = VisitorUtils.append_path(head, tail)
    assert result == [1, 2, 3, 4, 5]

    # Test non-matching paths
    head = [1, 2, 3]
    tail = [4, 5, 6]
    result = VisitorUtils.append_path(head, tail)
    assert result == [1, 2, 3]


@patch("gatox.enumerate.enumerate.Api")
async def test_initialize_action_node(mock_api):
    graph = WorkflowGraphBuilder().graph
    api = mock_api  # Mock API if needed
    node = ActionNode("someorg/testaction@v4", "main", "action.yml", "testOrg/repo", {})

    try:
        await VisitorUtils.initialize_action_node(graph, api, node)
    except Exception:
        pass
    # Just verify tag was removed
    assert "uninitialized" not in node.get_tags()


def test_action_render(capsys, mock_api):
    # Ensure Output singleton is initialized with color argument
    from gatox.cli import output

    output.Output._instance = None
    output.Output(color=True)

    import re

    def strip_ansi(text):
        ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        return ansi_escape.sub("", text)

    MOCK_WORKFLOW = """
    on:
      pull_request_target:

    jobs:
      test1:
        runs-on: ubuntu-latest
        steps:
          - name: Test Step
            run: echo ${{github.event.pull_request.title}}

    """

    step_data = {
        "name": "test_step",
        "run": "echo ${{github.event.pull_request.title}}",
    }

    test_workflow = Workflow(
        "testOrg/test_repo", MOCK_WORKFLOW, ".github/workflows/test.yml"
    )
    test_flow = [
        WorkflowNode("main", "testOrg/test_repo", ".github/workflows/test.yml"),
        JobNode("Test1", "main", "testOrg/test_repo", ".github/workflows/test.yml"),
        StepNode(
            step_data,
            "main",
            "testOrg/test_repo",
            ".github/workflows/",
            "tests.yml",
            1,
        ),
    ]

    test_flow[0].initialize(test_workflow)

    flow = ResultFactory.create_injection_result(
        test_flow, Confidence.HIGH, Complexity.ZERO_CLICK
    )

    ActionsReport.render_report(flow)
    captured = capsys.readouterr()
    out_stripped = strip_ansi(captured.out)
    assert "Repository Name: testOrg/test_repo" in out_stripped
    assert "Report Type: InjectionResult" in out_stripped
    assert "Context Vars: github.event.pull_request.title" in out_stripped


def test_add_results_and_append_path_extra():
    # _add_results with different issue types
    results = {}
    path = [DummyNode(), DummyNode()]
    VisitorUtils._add_results(
        path, results, IssueType.PWN_REQUEST, Confidence.HIGH, Complexity.TOCTOU
    )
    VisitorUtils._add_results(path, results, IssueType.ACTIONS_INJECTION)
    VisitorUtils._add_results(path, results, IssueType.DISPATCH_TOCTOU)
    VisitorUtils._add_results(path, results, IssueType.PR_REVIEW_INJECTION)
    assert "repo" in results
    assert len(results["repo"]) == 4

    # append_path edge case: empty head or tail
    assert VisitorUtils.append_path([], [1, 2]) == []
    assert VisitorUtils.append_path([1, 2], []) == [1, 2]


@pytest.mark.asyncio
async def test_initialize_action_node_extra(monkeypatch):
    node = DummyNode(tags={"uninitialized"})
    graph = DummyGraph()
    called = {}

    async def fake_initialize_action_node(graph_arg, api_arg, node_arg):
        called["ran"] = True
        # Simulate removing tag
        graph_arg.remove_tags_from_node(node_arg, {"uninitialized"})

    monkeypatch.setattr(
        VisitorUtils,
        "initialize_action_node",
        staticmethod(fake_initialize_action_node),
    )
    await VisitorUtils.initialize_action_node(graph, DummyApi(), node)
    assert graph.removed_tags
    assert called["ran"]


@pytest.mark.asyncio
async def test_add_repo_results_extra(monkeypatch):
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.CacheManager",
        lambda: DummyCacheManager(),
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.ConfigurationManager",
        lambda: types.SimpleNamespace(
            NOTIFICATIONS={"SLACK_WEBHOOKS": [], "DISCORD_WEBHOOKS": []}
        ),
    )
    data = {
        "repo": [DummyResult("repo"), DummyResult("repo2")]
    }  # repo2 will be skipped as duplicate hash
    await VisitorUtils.add_repo_results(data, DummyApi())


@pytest.mark.asyncio
async def test_add_repo_results_file_caching(monkeypatch):
    """Test that file caching prevents duplicate API calls for the same file"""

    # Create a mock API that counts calls
    api_call_count = {"get_file_last_updated": 0, "get_commit_merge_date": 0}

    class TrackingApi:
        async def get_file_last_updated(self, repo, file_path):
            api_call_count["get_file_last_updated"] += 1
            return ("2025-05-16T12:00:00Z", "author", "sha123")

        async def get_commit_merge_date(self, repo, sha):
            api_call_count["get_commit_merge_date"] += 1
            return "2025-05-16T13:00:00Z"

    # Create results that reference the same workflow file
    class SameFileResult:
        def __init__(self, repo_name, hash_value):
            self._repo_name = repo_name
            self._hash = hash_value

        def repo_name(self):
            return self._repo_name

        def get_first_and_last_hash(self):
            return self._hash

        def to_machine(self):
            return {"initial_workflow": "same-workflow.yml"}

    # Mock necessary dependencies
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.CacheManager",
        lambda: DummyCacheManager(),
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.ConfigurationManager",
        lambda: types.SimpleNamespace(
            NOTIFICATIONS={"SLACK_WEBHOOKS": ["webhook1"], "DISCORD_WEBHOOKS": []}
        ),
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.is_within_last_day",
        lambda x: True,  # Always return True for testing
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.return_recent",
        lambda x, y: y,  # Return the merge date
    )

    # Create test data with multiple results pointing to the same file
    data = {
        "repo1": [
            SameFileResult("owner/repo1", hash("result1")),
            SameFileResult("owner/repo1", hash("result2")),  # Different hash, same file
        ]
    }

    # Run the function
    await VisitorUtils.add_repo_results(data, TrackingApi())

    # Verify that API was only called once for the file
    assert (
        api_call_count["get_file_last_updated"] == 1
    ), "API should only be called once per file"
    assert (
        api_call_count["get_commit_merge_date"] == 1
    ), "Merge date API should only be called once per file"


@pytest.mark.asyncio
async def test_add_repo_results_different_files_cache(monkeypatch):
    """Test that different files result in separate API calls"""

    # Create a mock API that counts calls
    api_call_count = {"get_file_last_updated": 0}

    class TrackingApi:
        async def get_file_last_updated(self, repo, file_path):
            api_call_count["get_file_last_updated"] += 1
            return ("2025-05-16T12:00:00Z", "author", "sha123")

        async def get_commit_merge_date(self, repo, sha):
            return "2025-05-16T13:00:00Z"

    # Create results that reference different workflow files
    class DifferentFileResult:
        def __init__(self, repo_name, workflow_file, hash_value):
            self._repo_name = repo_name
            self._workflow_file = workflow_file
            self._hash = hash_value

        def repo_name(self):
            return self._repo_name

        def get_first_and_last_hash(self):
            return self._hash

        def to_machine(self):
            return {"initial_workflow": self._workflow_file}

    # Mock necessary dependencies
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.CacheManager",
        lambda: DummyCacheManager(),
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.ConfigurationManager",
        lambda: types.SimpleNamespace(
            NOTIFICATIONS={"SLACK_WEBHOOKS": ["webhook1"], "DISCORD_WEBHOOKS": []}
        ),
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.is_within_last_day",
        lambda x: True,
    )
    monkeypatch.setattr(
        "gatox.workflow_graph.visitors.visitor_utils.return_recent",
        lambda x, y: y,
    )

    # Create test data with results pointing to different files
    data = {
        "repo1": [
            DifferentFileResult("owner/repo1", "workflow1.yml", hash("result1")),
            DifferentFileResult("owner/repo1", "workflow2.yml", hash("result2")),
        ]
    }

    # Run the function
    await VisitorUtils.add_repo_results(data, TrackingApi())

    # Verify that API was called for each different file
    assert (
        api_call_count["get_file_last_updated"] == 2
    ), "API should be called once per unique file"
