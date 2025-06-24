import pytest
from unittest.mock import MagicMock, patch
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType


@pytest.fixture
def mock_graph():
    return MagicMock(spec=TaggedGraph)


@pytest.fixture
def mock_api():
    return MagicMock(spec=Api)


@pytest.fixture
def mock_cache_manager():
    with patch(
        "gatox.workflow_graph.visitors.pwn_request_visitor.CacheManager"
    ) as MockCache:
        instance = MockCache.return_value
        instance.get_repository.return_value = MagicMock(is_fork=lambda: False)
        yield instance


async def test_find_pwn_requests_no_nodes(mock_graph, mock_api, mock_cache_manager):
    mock_graph.get_nodes_for_tags.return_value = []
    with patch.object(VisitorUtils, "add_repo_results"):
        await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)


async def test_find_pwn_requests_with_nodes(mock_graph, mock_api, mock_cache_manager):
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]
    mock_graph.dfs_to_tag.return_value = [[node]]

    with (
        patch.object(PwnRequestVisitor, "_process_single_path") as mock_process,
        patch.object(VisitorUtils, "add_repo_results"),
    ):
        await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
        mock_process.assert_called_once()


async def test_process_single_path_with_memoization_logic(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that permission blockers and approval gates are memoized correctly,
    and results are only suppressed when blocker nodes are actually in the final path.
    """
    # Create mock nodes for the path
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    # Create mock blocker and approval gate nodes (not in main path)
    blocker_node = MagicMock()
    blocker_node.get_tags.return_value = ["permission_blocker"]

    approval_gate_node = MagicMock()
    approval_gate_node.get_tags.return_value = ["permission_check"]

    # Create sink node
    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Set up the path
    path = [workflow_node, job_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            # Return paths to blocker nodes that are NOT in the main path
            return [[blocker_node]]
        elif tag == "permission_check":
            # Return paths to approval gate nodes that are NOT in the main path
            return [[approval_gate_node]]
        elif tag == "sink":
            # Return sink path
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were added (since blocker nodes are not in the main path)
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args

        # Check that the path was passed correctly
        assert call_args[0][0] == path
        assert call_args[0][1] == results
        assert call_args[0][2] == IssueType.PWN_REQUEST

        # Verify complexity and confidence
        assert (
            call_args[1]["complexity"] == Complexity.ZERO_CLICK
        )  # No approval gate in path
        assert call_args[1]["confidence"] == Confidence.HIGH  # Sink found


async def test_process_single_path_blocker_in_path_suppresses_results(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that results are suppressed when a blocker node is actually in the final path.
    """
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    # This blocker node is part of the main path
    blocker_step = MagicMock()
    blocker_step.get_tags.return_value = ["StepNode", "permission_blocker"]
    blocker_step.is_checkout = False
    blocker_step.outputs = None
    blocker_step.hard_gate = False
    blocker_step.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Path includes the blocker node
    path = [workflow_node, job_node, blocker_step, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            # Return path that includes the blocker_step (which is in main path)
            return [[blocker_step]]
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were NOT added (blocker node is in the path)
        mock_add_results.assert_not_called()


async def test_process_single_path_approval_gate_affects_complexity(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that approval gate nodes in the path correctly affect complexity calculation.
    """
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    # This approval gate node is part of the main path
    approval_step = MagicMock()
    approval_step.get_tags.return_value = ["StepNode", "permission_check"]
    approval_step.is_checkout = False
    approval_step.outputs = None
    approval_step.hard_gate = False
    approval_step.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Path includes the approval gate node
    path = [workflow_node, job_node, approval_step, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            # Return path that includes the approval_step (which is in main path)
            return [[approval_step]]
        elif tag == "sink":
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were added
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args

        # Check that complexity is TOCTOU due to effective approval gate
        assert call_args[1]["complexity"] == Complexity.TOCTOU
        assert call_args[1]["confidence"] == Confidence.HIGH


@pytest.mark.asyncio
async def test_process_single_path_job_node_with_deployments(
    mock_graph, mock_api, mock_cache_manager
):
    """Test job node with deployment environment rules"""
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = ["production", {"name": "staging"}]
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, job_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API to return environment rules that include our deployment
    mock_api.get_all_environment_protection_rules.return_value = {
        "production": {"required_reviewers": 1}
    }

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="production"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should call API to get environment protection rules
        mock_api.get_all_environment_protection_rules.assert_called_once_with(
            "test/repo"
        )

        # Verify approval gate was triggered and complexity is TOCTOU
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["complexity"] == Complexity.TOCTOU


@pytest.mark.asyncio
async def test_process_single_path_job_node_with_outputs_and_env_lookup(
    mock_graph, mock_api, mock_cache_manager
):
    """Test job node with outputs that reference environment variables"""
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {"MY_VAR": "github.event.repository.name"}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = {
        "output1": "env.MY_VAR",  # References environment variable
        "output2": "static_value",  # Static value
        "output3": 123,  # Non-string value
    }
    job_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "inputs.output1"  # Uses job output
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, job_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="output1"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should process the job outputs and environment variables
        mock_add_results.assert_called_once()


@pytest.mark.asyncio
async def test_process_single_path_step_node_with_outputs_and_env(
    mock_graph, mock_api, mock_cache_manager
):
    """Test step node with outputs containing environment references"""
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode"]
    step_node.is_checkout = False
    step_node.outputs = {"step_output": "env.SOME_VAR"}
    step_node.hard_gate = False
    step_node.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, step_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should process step outputs
        mock_add_results.assert_called_once()


@pytest.mark.asyncio
async def test_process_single_path_workflow_node_fork_repository(mock_graph, mock_api):
    """Test workflow node with fork repository detection"""
    with patch(
        "gatox.workflow_graph.visitors.pwn_request_visitor.CacheManager"
    ) as MockCache:
        # Mock fork repository
        fork_repo = MagicMock()
        fork_repo.is_fork.return_value = True
        instance = MockCache.return_value
        instance.get_repository.return_value = fork_repo

        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
        workflow_node.excluded.return_value = False
        workflow_node.get_env_vars.return_value = {}
        workflow_node.repo_name.return_value = "fork/repo"

        step_node = MagicMock()
        step_node.get_tags.return_value = ["StepNode"]
        step_node.is_checkout = True
        step_node.metadata = "refs/heads/main"
        step_node.outputs = None
        step_node.hard_gate = False
        step_node.soft_gate = False

        path = [workflow_node, step_node]

        mock_graph.dfs_to_tag.return_value = []
        mock_api.get_all_environment_protection_rules.return_value = {}

        results = {}
        rule_cache = {}

        with patch.object(VisitorUtils, "_add_results") as mock_add_results:
            await PwnRequestVisitor._process_single_path(
                path, mock_graph, mock_api, rule_cache, results
            )

            # Should break early due to fork repository, no results added
            mock_add_results.assert_not_called()


@pytest.mark.asyncio
async def test_process_single_path_workflow_node_excluded(
    mock_graph, mock_api, mock_cache_manager
):
    """Test workflow node with excluded flag"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = True  # Excluded workflow
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode"]
    step_node.is_checkout = True
    step_node.metadata = "refs/heads/main"

    path = [workflow_node, step_node]

    mock_graph.dfs_to_tag.return_value = []
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with patch.object(VisitorUtils, "_add_results") as mock_add_results:
        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should break early due to excluded workflow, no results added
        mock_add_results.assert_not_called()


@pytest.mark.asyncio
async def test_process_single_path_workflow_node_labeled_trigger(
    mock_graph, mock_api, mock_cache_manager
):
    """Test workflow node with pull_request_target:labeled trigger"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = [
        "WorkflowNode",
        "pull_request_target:labeled",
    ]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should set approval gate due to labeled trigger and use TOCTOU complexity
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["complexity"] == Complexity.TOCTOU


@pytest.mark.asyncio
async def test_process_single_path_workflow_run_trigger(
    mock_graph, mock_api, mock_cache_manager
):
    """Test workflow_run trigger affects complexity"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "workflow_run"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should use PREVIOUS_CONTRIBUTOR complexity for workflow_run
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["complexity"] == Complexity.PREVIOUS_CONTRIBUTOR


@pytest.mark.asyncio
async def test_process_single_path_step_node_hard_gate(
    mock_graph, mock_api, mock_cache_manager
):
    """Test step node with hard gate breaks execution"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    hard_gate_step = MagicMock()
    hard_gate_step.get_tags.return_value = ["StepNode"]
    hard_gate_step.is_checkout = False
    hard_gate_step.outputs = None
    hard_gate_step.hard_gate = True  # Hard gate
    hard_gate_step.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, hard_gate_step, checkout_step]

    mock_graph.dfs_to_tag.return_value = []
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with patch.object(VisitorUtils, "_add_results") as mock_add_results:
        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should break at hard gate, no results added
        mock_add_results.assert_not_called()


@pytest.mark.asyncio
async def test_process_single_path_step_node_soft_gate(
    mock_graph, mock_api, mock_cache_manager
):
    """Test step node with soft gate sets approval gate"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    soft_gate_step = MagicMock()
    soft_gate_step.get_tags.return_value = ["StepNode"]
    soft_gate_step.is_checkout = False
    soft_gate_step.outputs = None
    soft_gate_step.hard_gate = False
    soft_gate_step.soft_gate = True  # Soft gate

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, soft_gate_step, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should set approval gate due to soft gate and use TOCTOU complexity
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["complexity"] == Complexity.TOCTOU


@pytest.mark.asyncio
async def test_process_single_path_action_node_initialization(
    mock_graph, mock_api, mock_cache_manager
):
    """Test action node initialization"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    action_node = MagicMock()
    action_node.get_tags.return_value = ["ActionNode"]

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, action_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "initialize_action_node") as mock_init_action,
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should initialize action node
        mock_init_action.assert_called_once_with(mock_graph, mock_api, action_node)
        mock_add_results.assert_called_once()


@pytest.mark.asyncio
async def test_process_single_path_checkout_with_env_metadata(
    mock_graph, mock_api, mock_cache_manager
):
    """Test checkout step with environment variable in metadata"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {
        "REF": "github.event.repository.default_branch"
    }
    workflow_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "env.REF"  # References environment variable
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="REF"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should process environment variable lookup in checkout metadata
        mock_add_results.assert_called_once()


@pytest.mark.asyncio
async def test_process_single_path_no_sinks_unknown_confidence(
    mock_graph, mock_api, mock_cache_manager
):
    """Test path with no sinks results in unknown confidence"""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, checkout_step]

    # Mock the graph DFS calls - no sinks
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return []  # No sinks
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Should use UNKNOWN confidence when no sinks found
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["confidence"] == Confidence.UNKNOWN


@pytest.mark.asyncio
async def test_find_pwn_requests_ignore_workflow_run(
    mock_graph, mock_api, mock_cache_manager
):
    """Test find_pwn_requests with ignore_workflow_run=True"""
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]
    mock_graph.dfs_to_tag.return_value = [[node]]

    with patch.object(PwnRequestVisitor, "_process_single_path"):
        await PwnRequestVisitor.find_pwn_requests(
            mock_graph, mock_api, ignore_workflow_run=True
        )

        # Should not include workflow_run in query taglist
        expected_tags = [
            "issue_comment",
            "pull_request_target",
            "pull_request_target:labeled",
        ]
        mock_graph.get_nodes_for_tags.assert_called_once_with(expected_tags)


@pytest.mark.asyncio
async def test_find_pwn_requests_with_dfs_exception(
    mock_graph, mock_api, mock_cache_manager
):
    """Test find_pwn_requests handles DFS exceptions gracefully"""
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]

    # Mock DFS to raise an exception
    mock_graph.dfs_to_tag.side_effect = Exception("DFS error")

    # Should not raise exception, just log error
    result = await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
    assert result == {}


@pytest.mark.asyncio
async def test_find_pwn_requests_with_process_path_exception(
    mock_graph, mock_api, mock_cache_manager
):
    """Test find_pwn_requests handles path processing exceptions gracefully"""
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]
    mock_graph.dfs_to_tag.return_value = [[node]]

    with patch.object(
        PwnRequestVisitor,
        "_process_single_path",
        side_effect=Exception("Process error"),
    ):
        # Should not raise exception, just log warning
        result = await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
        assert result == {}


@pytest.mark.asyncio
async def test_process_single_path_deployment_rule_substring_match(
    mock_graph, mock_api, mock_cache_manager
):
    """Test that deployment matches rule via substring (rule='prod', deployment='production')."""
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = ["production"]
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    path = [workflow_node, job_node, checkout_step]

    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[MagicMock()]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect
    # The rule is 'prod', which is a substring of 'production'
    mock_api.get_all_environment_protection_rules.return_value = ["prod"]

    results = {}
    rule_cache = {}

    with (
        patch.object(VisitorUtils, "process_context_var", side_effect=lambda x: x),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):
        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )
        # Should trigger approval gate due to substring match and set TOCTOU complexity
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args
        assert call_args[1]["complexity"] == Complexity.TOCTOU
