"""
Unit tests for ArtifactPoisoningVisitor
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from gatox.workflow_graph.visitors.artifact_poisoning_visitor import (
    ArtifactPoisoningVisitor,
)
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType


@pytest.fixture
def mock_graph():
    """Mock TaggedGraph fixture"""
    return MagicMock(spec=TaggedGraph)


@pytest.fixture
def mock_api():
    """Mock Api fixture"""
    return MagicMock(spec=Api)


@pytest.fixture
def mock_cache_manager():
    """Mock CacheManager fixture"""
    with patch(
        "gatox.workflow_graph.visitors.artifact_poisoning_visitor.CacheManager"
    ) as MockCache:
        instance = MockCache.return_value
        instance.get_repository.return_value = MagicMock(is_fork=lambda: False)
        yield instance


class TestArtifactPoisoningVisitor:
    """Test cases for ArtifactPoisoningVisitor"""

    async def test_find_artifact_poisoning_no_workflow_run_nodes(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test when no workflow_run nodes are found"""
        mock_graph.get_nodes_for_tags.return_value = []

        result = await ArtifactPoisoningVisitor.find_artifact_poisoning(
            mock_graph, mock_api
        )

        assert result == {}
        mock_graph.get_nodes_for_tags.assert_called_once_with(["workflow_run"])

    async def test_find_artifact_poisoning_no_artifact_paths(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test when workflow_run nodes exist but no paths to artifacts"""
        workflow_run_node = MagicMock()
        mock_graph.get_nodes_for_tags.return_value = [workflow_run_node]
        mock_graph.dfs_to_tag.return_value = None

        result = await ArtifactPoisoningVisitor.find_artifact_poisoning(
            mock_graph, mock_api
        )

        assert result == {}
        mock_graph.dfs_to_tag.assert_called_once_with(
            workflow_run_node, "artifact", mock_api
        )

    async def test_find_artifact_poisoning_with_artifact_paths(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test when workflow_run nodes exist with paths to artifacts"""
        workflow_run_node = MagicMock()
        artifact_node = MagicMock()
        mock_path = [workflow_run_node, artifact_node]

        mock_graph.get_nodes_for_tags.return_value = [workflow_run_node]
        mock_graph.dfs_to_tag.return_value = [mock_path]

        with patch.object(
            ArtifactPoisoningVisitor,
            "_ArtifactPoisoningVisitor__process_path",
            new_callable=AsyncMock,
        ) as mock_process:
            result = await ArtifactPoisoningVisitor.find_artifact_poisoning(
                mock_graph, mock_api
            )

            mock_process.assert_called_once_with(
                mock_path, mock_graph, mock_api, result
            )

    async def test_find_artifact_poisoning_with_multiple_paths(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test when multiple workflow_run nodes exist with multiple paths"""
        workflow_run_node1 = MagicMock()
        workflow_run_node2 = MagicMock()
        artifact_node1 = MagicMock()
        artifact_node2 = MagicMock()

        mock_path1 = [workflow_run_node1, artifact_node1]
        mock_path2 = [workflow_run_node2, artifact_node2]

        mock_graph.get_nodes_for_tags.return_value = [
            workflow_run_node1,
            workflow_run_node2,
        ]

        # Simulate each node returning different paths
        def mock_dfs_side_effect(node, tag, api):
            if node == workflow_run_node1:
                return [mock_path1]
            elif node == workflow_run_node2:
                return [mock_path2]
            return None

        mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

        with patch.object(
            ArtifactPoisoningVisitor,
            "_ArtifactPoisoningVisitor__process_path",
            new_callable=AsyncMock,
        ) as mock_process:
            await ArtifactPoisoningVisitor.find_artifact_poisoning(mock_graph, mock_api)

            # Should be called twice, once for each path
            assert mock_process.call_count == 2

    async def test_find_artifact_poisoning_handles_exceptions(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test that exceptions during path processing are handled gracefully"""
        workflow_run_node = MagicMock()
        artifact_node = MagicMock()
        mock_path = [workflow_run_node, artifact_node]

        mock_graph.get_nodes_for_tags.return_value = [workflow_run_node]
        mock_graph.dfs_to_tag.return_value = [mock_path]

        with patch.object(
            ArtifactPoisoningVisitor,
            "_ArtifactPoisoningVisitor__process_path",
            new_callable=AsyncMock,
            side_effect=Exception("Test exception"),
        ) as mock_process:
            # Should not raise an exception
            result = await ArtifactPoisoningVisitor.find_artifact_poisoning(
                mock_graph, mock_api
            )

            # Result should be an empty dict since processing failed
            assert result == {}
            mock_process.assert_called_once()

    async def test_process_path_with_workflow_node_fork_repo(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when WorkflowNode comes from a fork repository"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"

        # Configure cache manager to return a fork
        mock_cache_manager.get_repository.return_value = MagicMock(is_fork=lambda: True)

        path = [workflow_node]
        results = {}

        await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should not add any results for fork repositories
        assert results == {}

    async def test_process_path_with_workflow_node_excluded(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when WorkflowNode is excluded"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = True

        path = [workflow_node]
        results = {}

        await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should not add any results for excluded workflows
        assert results == {}

    async def test_process_path_with_job_node_input_params(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when JobNode provides input parameters"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        job_node = MagicMock()
        job_node.get_tags.return_value = ["JobNode"]
        job_node.params = {"input1": "value1", "input2": "value2"}

        path = [job_node, workflow_node]
        results = {}

        await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should process without error - input_lookup should be updated internally
        # but we can't directly verify since it's internal to the method

    async def test_process_path_with_action_node_artifact_and_sink(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when ActionNode has artifact tag and leads to sink"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        action_node = MagicMock()
        action_node.get_tags.return_value = ["ActionNode", "artifact"]

        sink_node = MagicMock()
        sink_node.get_tags.return_value = ["sink"]

        path = [workflow_node, action_node]
        results = {}

        # Mock DFS to sink to return a path with sink
        mock_graph.dfs_to_tag.return_value = [[sink_node]]

        with (
            patch.object(VisitorUtils, "initialize_action_node") as mock_init,
            patch.object(VisitorUtils, "append_path") as mock_append,
            patch.object(VisitorUtils, "_add_results") as mock_add_results,
        ):

            await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Verify that action node was initialized
            mock_init.assert_called_once_with(mock_graph, mock_api, action_node)

            # Verify DFS to sink was called
            mock_graph.dfs_to_tag.assert_called_once_with(action_node, "sink", mock_api)

            # Verify path was appended
            mock_append.assert_called_once_with(path, [sink_node])

            # Verify results were added
            mock_add_results.assert_called_once_with(
                path,
                results,
                IssueType.ARTIFACT_POISONING,
                complexity=Complexity.PREVIOUS_CONTRIBUTOR,
                confidence=Confidence.MEDIUM,
            )

    async def test_process_path_with_action_node_artifact_no_sink(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when ActionNode has artifact tag but no sink found"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        action_node = MagicMock()
        action_node.get_tags.return_value = ["ActionNode", "artifact"]

        path = [workflow_node, action_node]
        results = {}

        # Mock DFS to sink to return empty list (no sinks found)
        mock_graph.dfs_to_tag.return_value = []

        with (
            patch.object(VisitorUtils, "initialize_action_node") as mock_init,
            patch.object(VisitorUtils, "append_path") as mock_append,
            patch.object(VisitorUtils, "_add_results") as mock_add_results,
        ):

            await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Verify that action node was initialized
            mock_init.assert_called_once_with(mock_graph, mock_api, action_node)

            # Verify DFS to sink was called
            mock_graph.dfs_to_tag.assert_called_once_with(action_node, "sink", mock_api)

            # Verify path was NOT appended (no sinks)
            mock_append.assert_not_called()

            # Verify results were NOT added (no sinks)
            mock_add_results.assert_not_called()

    async def test_process_path_with_action_node_no_artifact_tag(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path when ActionNode doesn't have artifact tag"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        action_node = MagicMock()
        action_node.get_tags.return_value = ["ActionNode"]  # No artifact tag

        path = [workflow_node, action_node]
        results = {}

        with (
            patch.object(VisitorUtils, "initialize_action_node") as mock_init,
            patch.object(VisitorUtils, "_add_results") as mock_add_results,
        ):

            await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Verify that action node was initialized
            mock_init.assert_called_once_with(mock_graph, mock_api, action_node)

            # Verify DFS to sink was NOT called (no artifact tag)
            mock_graph.dfs_to_tag.assert_not_called()

            # Verify results were NOT added (no artifact)
            mock_add_results.assert_not_called()

    async def test_process_path_mixed_node_types(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path with a mix of different node types"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        job_node = MagicMock()
        job_node.get_tags.return_value = ["JobNode"]
        job_node.params = {"test_param": "test_value"}

        step_node = MagicMock()
        step_node.get_tags.return_value = ["StepNode"]

        action_node = MagicMock()
        action_node.get_tags.return_value = ["ActionNode", "artifact"]

        sink_node = MagicMock()
        sink_node.get_tags.return_value = ["sink"]

        # Path: job -> workflow -> step -> action
        path = [job_node, workflow_node, step_node, action_node]
        results = {}

        # Mock DFS to sink
        mock_graph.dfs_to_tag.return_value = [[sink_node]]

        with (
            patch.object(VisitorUtils, "initialize_action_node") as mock_init,
            patch.object(VisitorUtils, "append_path") as _,
            patch.object(VisitorUtils, "_add_results") as mock_add_results,
        ):

            await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Should initialize action node and add results
            mock_init.assert_called_once_with(mock_graph, mock_api, action_node)
            mock_add_results.assert_called_once()

    async def test_process_path_empty_path(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path with empty path"""
        path = []
        results = {}

        await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should handle empty path gracefully
        assert results == {}

    async def test_process_path_unknown_node_type(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test __process_path with unknown node type"""
        unknown_node = MagicMock()
        unknown_node.get_tags.return_value = ["UnknownNode"]

        path = [unknown_node]
        results = {}

        await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should handle unknown node types gracefully
        assert results == {}

    def test_visitor_imports_and_structure(self):
        """Test that the visitor has the expected structure and imports"""
        # Verify the visitor class exists and has expected methods
        assert hasattr(ArtifactPoisoningVisitor, "find_artifact_poisoning")
        assert hasattr(
            ArtifactPoisoningVisitor, "_ArtifactPoisoningVisitor__process_path"
        )

        # Verify the methods are static
        assert isinstance(
            ArtifactPoisoningVisitor.__dict__["find_artifact_poisoning"], staticmethod
        )
        assert isinstance(
            ArtifactPoisoningVisitor.__dict__[
                "_ArtifactPoisoningVisitor__process_path"
            ],
            staticmethod,
        )

    async def test_integration_with_visitor_utils(
        self, mock_graph, mock_api, mock_cache_manager
    ):
        """Test integration with VisitorUtils methods"""
        workflow_node = MagicMock()
        workflow_node.get_tags.return_value = ["WorkflowNode"]
        workflow_node.repo_name.return_value = "test/repo"
        workflow_node.excluded.return_value = False

        action_node = MagicMock()
        action_node.get_tags.return_value = ["ActionNode", "artifact"]

        sink_node = MagicMock()

        path = [workflow_node, action_node]
        results = {}

        mock_graph.dfs_to_tag.return_value = [[sink_node]]

        # Test that all VisitorUtils methods are called with correct parameters
        with (
            patch.object(VisitorUtils, "initialize_action_node") as mock_init,
            patch.object(VisitorUtils, "append_path", return_value=path) as mock_append,
            patch.object(VisitorUtils, "_add_results") as mock_add_results,
        ):

            await ArtifactPoisoningVisitor._ArtifactPoisoningVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Verify correct parameters passed to VisitorUtils methods
            mock_init.assert_called_once_with(mock_graph, mock_api, action_node)
            mock_append.assert_called_once_with(path, [sink_node])
            mock_add_results.assert_called_once_with(
                path,
                results,
                IssueType.ARTIFACT_POISONING,
                complexity=Complexity.PREVIOUS_CONTRIBUTOR,
                confidence=Confidence.MEDIUM,
            )
