"""
Unit tests for RunnerVisitor
"""

import pytest
from unittest.mock import MagicMock, patch
from gatox.workflow_graph.visitors.runner_visitor import RunnerVisitor
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


@pytest.fixture
def mock_graph():
    """Mock TaggedGraph fixture"""
    return MagicMock(spec=TaggedGraph)


@pytest.fixture
def mock_cache_manager():
    """Mock CacheManager fixture"""
    with patch(
        "gatox.workflow_graph.visitors.runner_visitor.CacheManager"
    ) as MockCache:
        instance = MockCache.return_value
        yield instance


class TestRunnerVisitor:
    """Test cases for RunnerVisitor"""

    async def test_find_runner_workflows_no_nodes(self, mock_graph, mock_cache_manager):
        """Test when no self-hosted nodes are found"""
        mock_graph.get_nodes_for_tags.return_value = []

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        assert result == {}
        mock_graph.get_nodes_for_tags.assert_called_once_with(["self-hosted"])

    async def test_find_runner_workflows_simple_node(
        self, mock_graph, mock_cache_manager
    ):
        """Test with a simple self-hosted node"""
        # Setup mock node
        mock_node = MagicMock()
        mock_node.repo_name.return_value = "owner/repo"
        mock_node.get_workflow_name.return_value = "test-workflow"

        # Setup mock workflow
        mock_workflow = MagicMock()
        mock_workflow.get_tags.return_value = set()
        mock_node.get_workflow.return_value = mock_workflow

        # Setup mock cached repo
        mock_cached_repo = MagicMock()
        mock_cache_manager.get_repository.return_value = mock_cached_repo

        mock_graph.get_nodes_for_tags.return_value = [mock_node]

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        assert result == {"owner/repo": {"test-workflow"}}
        mock_cached_repo.add_self_hosted_workflows.assert_called_once_with(
            ["test-workflow"]
        )

    async def test_find_runner_workflows_workflow_call_node(
        self, mock_graph, mock_cache_manager
    ):
        """Test with a workflow_call node that has callers"""
        # Setup mock node
        mock_node = MagicMock()
        mock_node.repo_name.return_value = "owner/repo"
        mock_node.get_workflow_name.return_value = "reusable-workflow"

        # Setup mock workflow with workflow_call tag
        mock_workflow = MagicMock()
        mock_workflow.get_tags.return_value = {"workflow_call"}
        mock_node.get_workflow.return_value = mock_workflow

        # Setup mock caller workflows
        mock_caller1 = MagicMock()
        mock_caller1.get_workflow_name.return_value = "caller-workflow-1"
        mock_caller2 = MagicMock()
        mock_caller2.get_workflow_name.return_value = "caller-workflow-2"
        mock_workflow.get_caller_workflows.return_value = [mock_caller1, mock_caller2]

        # Setup mock cached repo
        mock_cached_repo = MagicMock()
        mock_cache_manager.get_repository.return_value = mock_cached_repo

        mock_graph.get_nodes_for_tags.return_value = [mock_node]

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        expected = {
            "owner/repo": {
                "reusable-workflow",
                "caller-workflow-1",
                "caller-workflow-2",
            }
        }
        assert result == expected
        mock_cached_repo.add_self_hosted_workflows.assert_called_once_with(
            ["reusable-workflow"]
        )

    async def test_find_runner_workflows_no_cached_repo(
        self, mock_graph, mock_cache_manager
    ):
        """Test when cached repository is not available"""
        # Setup mock node
        mock_node = MagicMock()
        mock_node.repo_name.return_value = "owner/repo"
        mock_node.get_workflow_name.return_value = "test-workflow"

        # Setup mock workflow
        mock_workflow = MagicMock()
        mock_workflow.get_tags.return_value = set()
        mock_node.get_workflow.return_value = mock_workflow

        # No cached repo available
        mock_cache_manager.get_repository.return_value = None

        mock_graph.get_nodes_for_tags.return_value = [mock_node]

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        assert result == {"owner/repo": {"test-workflow"}}
        # Should not call add_self_hosted_workflows when no cached repo
        mock_cache_manager.get_repository.assert_called_once_with("owner/repo")

    async def test_find_runner_workflows_multiple_repos(
        self, mock_graph, mock_cache_manager
    ):
        """Test with nodes from multiple repositories"""
        # Setup mock nodes
        mock_node1 = MagicMock()
        mock_node1.repo_name.return_value = "owner/repo1"
        mock_node1.get_workflow_name.return_value = "workflow1"

        mock_node2 = MagicMock()
        mock_node2.repo_name.return_value = "owner/repo2"
        mock_node2.get_workflow_name.return_value = "workflow2"

        mock_node3 = MagicMock()
        mock_node3.repo_name.return_value = "owner/repo1"
        mock_node3.get_workflow_name.return_value = "workflow3"

        # Setup mock workflows
        for node in [mock_node1, mock_node2, mock_node3]:
            mock_workflow = MagicMock()
            mock_workflow.get_tags.return_value = set()
            node.get_workflow.return_value = mock_workflow

        # Setup mock cached repos
        mock_cached_repo = MagicMock()
        mock_cache_manager.get_repository.return_value = mock_cached_repo

        mock_graph.get_nodes_for_tags.return_value = [
            mock_node1,
            mock_node2,
            mock_node3,
        ]

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        expected = {
            "owner/repo1": {"workflow1", "workflow3"},
            "owner/repo2": {"workflow2"},
        }
        assert result == expected

    async def test_find_runner_workflows_exception_handling(
        self, mock_graph, mock_cache_manager
    ):
        """Test exception handling when processing nodes"""
        # Setup mock node that raises exception
        mock_node1 = MagicMock()
        mock_node1.repo_name.side_effect = Exception("Test error")
        mock_node1.name = "problematic-node"

        # Setup mock node that works normally
        mock_node2 = MagicMock()
        mock_node2.repo_name.return_value = "owner/repo"
        mock_node2.get_workflow_name.return_value = "test-workflow"
        mock_workflow = MagicMock()
        mock_workflow.get_tags.return_value = set()
        mock_node2.get_workflow.return_value = mock_workflow

        # Setup mock cached repo
        mock_cached_repo = MagicMock()
        mock_cache_manager.get_repository.return_value = mock_cached_repo

        mock_graph.get_nodes_for_tags.return_value = [mock_node1, mock_node2]

        with patch(
            "gatox.workflow_graph.visitors.runner_visitor.logger"
        ) as mock_logger:
            result = await RunnerVisitor.find_runner_workflows(mock_graph)

            # Should process the working node and skip the problematic one
            assert result == {"owner/repo": {"test-workflow"}}

            # Should log the error
            mock_logger.warning.assert_any_call(
                "Error processing node: problematic-node"
            )
            mock_logger.warning.assert_any_call(mock_node1.repo_name.side_effect)

    async def test_find_runner_workflows_empty_caller_workflows(
        self, mock_graph, mock_cache_manager
    ):
        """Test workflow_call node with no caller workflows"""
        # Setup mock node
        mock_node = MagicMock()
        mock_node.repo_name.return_value = "owner/repo"
        mock_node.get_workflow_name.return_value = "reusable-workflow"

        # Setup mock workflow with workflow_call tag but no callers
        mock_workflow = MagicMock()
        mock_workflow.get_tags.return_value = {"workflow_call"}
        mock_workflow.get_caller_workflows.return_value = []
        mock_node.get_workflow.return_value = mock_workflow

        # Setup mock cached repo
        mock_cached_repo = MagicMock()
        mock_cache_manager.get_repository.return_value = mock_cached_repo

        mock_graph.get_nodes_for_tags.return_value = [mock_node]

        result = await RunnerVisitor.find_runner_workflows(mock_graph)

        assert result == {"owner/repo": {"reusable-workflow"}}
        mock_cached_repo.add_self_hosted_workflows.assert_called_once_with(
            ["reusable-workflow"]
        )
