from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.workflow_graph.visitors.review_injection_visitor import (
    ReviewInjectionVisitor,
)


@pytest.fixture
def mock_api():
    return MagicMock()


@pytest.fixture
def mock_graph():
    return MagicMock()


@pytest.mark.asyncio
async def test_find_injections_no_nodes(mock_graph, mock_api):
    """Test when there are no nodes tagged with review injection triggers"""
    mock_graph.get_nodes_for_tags.return_value = []

    result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

    assert result == {}
    mock_graph.get_nodes_for_tags.assert_called_once_with(
        [
            "pull_request_review_comment",
            "pull_request_review",
        ]
    )


@pytest.mark.asyncio
async def test_find_injections_nodes_with_no_paths(mock_graph, mock_api):
    """Test when nodes exist but no injectable paths are found"""
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=None)

    result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

    assert result == {}
    mock_graph.dfs_to_tag.assert_called_once_with(mock_node, "injectable", mock_api)


@pytest.mark.asyncio
async def test_find_injections_empty_paths(mock_graph, mock_api):
    """Test when DFS returns empty paths"""
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[]])

    result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

    assert result == {}


@pytest.mark.asyncio
async def test_find_injections_job_node_with_deployments(mock_graph, mock_api):
    """Test processing JobNode with deployment environments"""
    # Create mock nodes
    mock_review_node = MagicMock()
    mock_job_node = MagicMock()
    mock_job_node.get_tags.return_value = ["JobNode"]
    mock_job_node.deployments = ["production"]
    mock_job_node.repo_name.return_value = "owner/repo"
    mock_job_node.get_env_vars.return_value = {}
    mock_job_node.outputs = None

    # Create path
    path = [mock_job_node]

    # Mock graph methods
    mock_graph.get_nodes_for_tags.return_value = [mock_review_node]
    mock_graph.dfs_to_tag = AsyncMock(
        side_effect=[
            [path],  # First call returns our path
            None,  # Second call (permission_check) returns None
        ]
    )

    # Mock API response for environment protection rules
    mock_api.get_all_environment_protection_rules = AsyncMock(
        return_value={"production": {"required_reviewers": 1}}
    )

    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils.check_deployment_approval_gate",
            new_callable=AsyncMock,
        ) as mock_check_deploy,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils.process_context_var"
        ) as mock_process_context_var,
    ):
        mock_check_deploy.return_value = True
        mock_process_context_var.return_value = "production"

        result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Should not add results due to approval gate being set
        assert result == {}


@pytest.mark.asyncio
async def test_find_injections_step_node_injectable_with_unsafe_context(
    mock_graph, mock_api
):
    """Test StepNode with injectable tag and unsafe context"""
    # Create mock nodes
    mock_review_node = MagicMock()
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
    mock_step_node.contexts = ["github.event.review.body"]  # Unsafe context

    # Create path
    path = [mock_step_node]

    # Mock graph methods
    mock_graph.get_nodes_for_tags.return_value = [mock_review_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_get_token,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_pr_review_unsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_get_token.return_value = "github.event.review.body"
        mock_pr_review_unsafe.return_value = True  # This is unsafe
        mock_visitor_utils._add_results.return_value = None

        result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Should add high confidence injection result
        mock_visitor_utils._add_results.assert_called_once_with(
            path, result, IssueType.PR_REVIEW_INJECTION, confidence=Confidence.HIGH
        )


@pytest.mark.asyncio
async def test_find_injections_step_node_injectable_with_body_context(
    mock_graph, mock_api
):
    """Test StepNode with injectable tag and 'body' in context"""
    # Create mock nodes
    mock_review_node = MagicMock()
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode", "injectable"]
    mock_step_node.contexts = ["some_body_value"]  # Contains 'body' but no 'github.'

    # Create path
    path = [mock_step_node]

    # Mock graph methods
    mock_graph.get_nodes_for_tags.return_value = [mock_review_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_get_token,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_pr_review_unsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_get_token.return_value = "some_body_value"  # Contains 'body'
        mock_pr_review_unsafe.return_value = False  # Not unsafe by prReviewUnsafe
        mock_visitor_utils._add_results.return_value = None

        result = await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Should add high confidence injection result because 'body' is in the value
        mock_visitor_utils._add_results.assert_called_once_with(
            path, result, IssueType.PR_REVIEW_INJECTION, confidence=Confidence.HIGH
        )


@pytest.mark.asyncio
async def test_find_injections_job_node_with_env_vars_and_outputs(mock_api, mock_graph):
    """Test job node with environment variables containing github contexts and outputs."""
    # Create a review node that matches the query tags
    review_node = MagicMock()
    review_node.get_tags.return_value = ["pull_request_review"]

    # Create job node with environment variables and outputs
    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.get_env_vars.return_value = {
        "VAR1": "github.event.review.body",  # Changed to review.body for unsafe context
        "VAR2": "some_value",
        "VAR3": "github.actor",
    }
    job_node.outputs = {
        "output1": "env.VAR1",
        "output2": "some_static_value",
        "output3": "env.VAR3",
    }

    # Create injectable step node - context that triggers injection
    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode", "injectable"]
    step_node.contexts = ["github.event.review.body"]  # Direct unsafe context

    # Mock graph methods - return the review_node for the query
    mock_graph.get_nodes_for_tags.return_value = [review_node]

    # Mock the permission check call to return empty (no approval gate)
    async def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_check":
            return []  # No permission paths found
        elif tag == "injectable":
            return [[job_node, step_node]]  # Return the injection path
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_getToken,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_prReviewUnsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_getToken.side_effect = lambda x: x
        mock_prReviewUnsafe.return_value = True

        await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Verify results were added due to unsafe context
        mock_visitor_utils._add_results.assert_called()


@pytest.mark.asyncio
async def test_find_injections_step_node_with_inputs_context(mock_api, mock_graph):
    """Test step node with inputs context processing."""
    # Create a review node that matches the query tags
    review_node = MagicMock()
    review_node.get_tags.return_value = ["pull_request_review"]

    # Create job node with environment lookup
    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.get_env_vars.return_value = {
        "INPUT_VAR": "github.event.review.body"
    }  # Unsafe context
    job_node.outputs = None

    # Create injectable step node with inputs context
    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode", "injectable"]
    step_node.contexts = ["${{ inputs.INPUT_VAR }}"]

    # Mock graph methods - return the review_node for the query
    mock_graph.get_nodes_for_tags.return_value = [review_node]

    # Mock the permission check call to return empty (no approval gate)
    async def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_check":
            return []  # No permission paths found
        elif tag == "injectable":
            return [[job_node, step_node]]  # Return the injection path
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock utility functions and regex
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.CONTEXT_REGEX"
        ) as mock_regex,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_getToken,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_prReviewUnsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_regex.findall.return_value = ["inputs.INPUT_VAR"]
        mock_getToken.side_effect = lambda x: x
        mock_prReviewUnsafe.return_value = True

        await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Verify the inputs processing path was taken
        mock_visitor_utils._add_results.assert_called()


@pytest.mark.asyncio
async def test_find_injections_step_node_with_env_context(mock_api, mock_graph):
    """Test step node with environment variable context processing."""
    # Create a review node that matches the query tags
    review_node = MagicMock()
    review_node.get_tags.return_value = ["pull_request_review"]

    # Create job node with environment lookup
    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.get_env_vars.return_value = {
        "GITHUB_VAR": "github.event.review.body"
    }  # Unsafe context
    job_node.outputs = None

    # Create injectable step node with env context
    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode", "injectable"]
    step_node.contexts = ["env.GITHUB_VAR"]

    # Mock graph methods - return the review_node for the query
    mock_graph.get_nodes_for_tags.return_value = [review_node]

    # Mock the permission check call to return empty (no approval gate)
    async def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_check":
            return []  # No permission paths found
        elif tag == "injectable":
            return [[job_node, step_node]]  # Return the injection path
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_getToken,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_prReviewUnsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_getToken.side_effect = lambda x: x
        mock_prReviewUnsafe.return_value = True

        await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Verify the env processing path was taken
        mock_visitor_utils._add_results.assert_called()


@pytest.mark.asyncio
async def test_find_injections_step_node_safe_github_context(mock_api, mock_graph):
    """Test step node with safe github context that should not trigger injection."""
    # Create job node
    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.get_env_vars.return_value = {}
    job_node.outputs = None

    # Create injectable step node with safe context
    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode", "injectable"]
    step_node.contexts = ["github.actor"]

    # Mock graph methods
    mock_graph.get_nodes_for_tags.return_value = [job_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[job_node, step_node]])

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_getToken,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_prReviewUnsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_getToken.side_effect = lambda x: x
        mock_prReviewUnsafe.return_value = False  # Safe context

        await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Verify no results were added due to safe context
        mock_visitor_utils._add_results.assert_not_called()


@pytest.mark.asyncio
async def test_find_injections_workflow_node_with_env_vars(mock_api, mock_graph):
    """Test workflow node with environment variables."""
    # Create workflow node with environment variables
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode"]
    workflow_node.get_env_vars.return_value = {
        "WORKFLOW_VAR": "github.event.review.body",
        "OTHER_VAR": "static_value",
    }

    # Create injectable step node
    step_node = MagicMock()
    step_node.get_tags.return_value = ["StepNode", "injectable"]
    step_node.contexts = ["env.WORKFLOW_VAR"]

    # Mock graph methods
    mock_graph.get_nodes_for_tags.return_value = [workflow_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[workflow_node, step_node]])

    # Mock utility functions
    with (
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.getToken"
        ) as mock_getToken,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.prReviewUnsafe"
        ) as mock_prReviewUnsafe,
        patch(
            "gatox.workflow_graph.visitors.review_injection_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_getToken.side_effect = lambda x: x
        mock_prReviewUnsafe.return_value = True

        await ReviewInjectionVisitor.find_injections(mock_graph, mock_api)

        # Verify workflow env vars were processed
        mock_visitor_utils._add_results.assert_called()
