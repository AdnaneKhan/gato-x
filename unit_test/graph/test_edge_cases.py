"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gatox.models.workflow import Workflow
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.nodes.workflow import WorkflowNode


class TestNonExistentWorkflowHandling:
    """Test cases for non-existent workflow handling functionality."""

    def test_workflow_node_initial_state(self):
        """Test that WorkflowNode starts in the correct initial state."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")

        assert workflow.uninitialized
        assert not workflow.non_existent
        assert not workflow.is_non_existent()

        tags = workflow.get_tags()
        assert "uninitialized" in tags
        assert "non_existent" not in tags
        assert "initialized" not in tags

    def test_workflow_node_mark_as_non_existent(self):
        """Test marking a workflow as non-existent."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")

        # Initially uninitialized
        assert workflow.uninitialized
        assert not workflow.non_existent

        # Mark as non-existent
        workflow.mark_as_non_existent()

        # Should now be non-existent
        assert not workflow.uninitialized
        assert workflow.non_existent
        assert workflow.is_non_existent()

        tags = workflow.get_tags()
        assert "non_existent" in tags
        assert "uninitialized" not in tags
        assert "initialized" not in tags

    def test_workflow_node_normal_initialization(self):
        """Test normal workflow initialization."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
        mock_workflow_data = MagicMock()
        mock_workflow_data.parsed_yml = {"on": ["push"], "env": {"TEST": "value"}}

        # Initially uninitialized
        assert workflow.uninitialized
        assert not workflow.non_existent

        # Initialize normally
        workflow.initialize(mock_workflow_data)

        # Should now be initialized
        assert not workflow.uninitialized
        assert not workflow.non_existent
        assert not workflow.is_non_existent()

        tags = workflow.get_tags()
        assert "initialized" in tags
        assert "uninitialized" not in tags
        assert "non_existent" not in tags

    def test_workflow_node_tags_priority(self):
        """Test that non_existent tag takes priority in get_tags()."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")

        # Start uninitialized
        tags = workflow.get_tags()
        assert "uninitialized" in tags

        # Mark as non-existent (should override uninitialized)
        workflow.mark_as_non_existent()
        tags = workflow.get_tags()
        assert "non_existent" in tags
        assert "uninitialized" not in tags
        assert "initialized" not in tags


class TestDFSWithNonExistentNodes:
    """Test cases for DFS behavior with non-existent nodes."""

    @pytest.mark.asyncio
    async def test_dfs_stops_at_non_existent_node(self):
        """Test that DFS stops traversal when encountering a non-existent node."""
        mock_builder = MagicMock()
        mock_builder.initialize_node = AsyncMock()

        graph = TaggedGraph(mock_builder)

        # Create nodes
        node1 = WorkflowNode("main", "test/repo", ".github/workflows/workflow1.yml")
        node2 = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")
        node3 = WorkflowNode("main", "test/repo", ".github/workflows/workflow3.yml")

        # Set up states
        node1.uninitialized = False  # initialized
        node2.mark_as_non_existent()  # non-existent
        node3.uninitialized = False  # initialized

        # Add nodes and edges
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_node(node3)
        graph.add_edge(node1, node2, relation="calls")
        graph.add_edge(node2, node3, relation="calls")

        # Add target tag to final node
        node3.extra_tags.add("target")
        graph.add_tag("target", [node3])

        # DFS should not reach node3 because it stops at non-existent node2
        mock_api = MagicMock()
        paths = await graph.dfs_to_tag(node1, "target", mock_api)

        assert len(paths) == 0
        # initialize_node should not be called since nodes are already processed
        mock_builder.initialize_node.assert_not_called()

    @pytest.mark.asyncio
    async def test_dfs_from_non_existent_start_node(self):
        """Test DFS starting from a non-existent node."""
        mock_builder = MagicMock()
        mock_builder.initialize_node = AsyncMock()

        graph = TaggedGraph(mock_builder)

        # Create non-existent start node
        start_node = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")
        target_node = WorkflowNode("main", "test/repo", ".github/workflows/target.yml")

        start_node.mark_as_non_existent()
        target_node.uninitialized = False

        graph.add_node(start_node)
        graph.add_node(target_node)
        graph.add_edge(start_node, target_node, relation="calls")
        target_node.extra_tags.add("target")
        graph.add_tag("target", [target_node])

        # DFS should return empty since start node is non-existent
        mock_api = MagicMock()
        paths = await graph.dfs_to_tag(start_node, "target", mock_api)

        assert len(paths) == 0

    @pytest.mark.asyncio
    async def test_dfs_with_multiple_paths_some_blocked(self):
        """Test DFS with multiple paths where some are blocked by non-existent nodes."""
        mock_builder = MagicMock()
        mock_builder.initialize_node = AsyncMock()

        graph = TaggedGraph(mock_builder)

        # Create a diamond-shaped graph
        start = WorkflowNode("main", "test/repo", ".github/workflows/start.yml")
        path1_middle = WorkflowNode(
            "main", "test/repo", ".github/workflows/missing1.yml"
        )
        path2_middle = WorkflowNode("main", "test/repo", ".github/workflows/good.yml")
        target = WorkflowNode("main", "test/repo", ".github/workflows/target.yml")

        # Set states
        start.uninitialized = False
        path1_middle.mark_as_non_existent()  # This path should be blocked
        path2_middle.uninitialized = False
        target.uninitialized = False

        # Add nodes and create diamond pattern
        for node in [start, path1_middle, path2_middle, target]:
            graph.add_node(node)

        graph.add_edge(start, path1_middle, relation="calls")  # blocked path
        graph.add_edge(start, path2_middle, relation="calls")  # good path
        graph.add_edge(path1_middle, target, relation="calls")
        graph.add_edge(path2_middle, target, relation="calls")

        # Add target tag to the target node's extra_tags so it shows up in get_tags()
        target.extra_tags.add("target")
        graph.add_tag("target", [target])

        # Should find only one path (through path2_middle)
        mock_api = MagicMock()
        paths = await graph.dfs_to_tag(start, "target", mock_api)

        # The DFS should find one path: start -> path2_middle -> target
        # The path through path1_middle should be blocked by the non_existent node
        assert len(paths) == 1, f"Expected 1 path, got {len(paths)} paths: {paths}"
        assert (
            len(paths[0]) == 3
        ), f"Expected path length 3, got {len(paths[0])}: {paths[0]}"
        assert paths[0][0] == start
        assert paths[0][1] == path2_middle
        assert paths[0][2] == target

    @pytest.mark.asyncio
    async def test_dfs_target_is_non_existent(self):
        """Test DFS when the target node itself is non-existent."""
        mock_builder = MagicMock()
        mock_builder.initialize_node = AsyncMock()

        graph = TaggedGraph(mock_builder)

        start = WorkflowNode("main", "test/repo", ".github/workflows/start.yml")
        target = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")

        start.uninitialized = False
        target.mark_as_non_existent()

        graph.add_node(start)
        graph.add_node(target)
        graph.add_edge(start, target, relation="calls")
        target.extra_tags.add("target")
        graph.add_tag("target", [target])  # target has the tag but is non-existent

        # Should not find any paths since target is non-existent
        mock_api = MagicMock()
        paths = await graph.dfs_to_tag(start, "target", mock_api)

        assert len(paths) == 0


class TestGraphBuilderNonExistentHandling:
    """Test cases for WorkflowGraphBuilder handling of non-existent workflows."""

    @pytest.mark.asyncio
    async def test_initialize_node_skips_non_existent(self):
        """Test that initialize_node skips nodes already marked as non-existent."""
        builder = WorkflowGraphBuilder()
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")
        workflow.mark_as_non_existent()

        mock_api = MagicMock()

        # Should not attempt initialization
        await builder.initialize_node(workflow, mock_api)

        # State should remain unchanged
        assert workflow.is_non_existent()
        assert not workflow.uninitialized

    @pytest.mark.asyncio
    async def test_initialize_callee_node_marks_non_existent(self):
        """Test that _initialize_callee_node marks workflows as non-existent when file not found."""
        builder = WorkflowGraphBuilder()
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/missing.yml")

        # Mock API to return None (file not found)
        mock_api = MagicMock()
        mock_api.retrieve_repo_file = AsyncMock(return_value=None)

        with (
            patch.object(builder.graph, "remove_tags_from_node"),
            patch.object(builder.graph, "add_tags_to_node"),
            patch(
                "gatox.caching.cache_manager.CacheManager.get_workflow",
                return_value=None,
            ),
            patch("gatox.caching.cache_manager.CacheManager.set_workflow"),
        ):

            # Should mark as non-existent
            await builder._initialize_callee_node(workflow, mock_api)

        # Verify workflow is marked as non-existent
        assert workflow.is_non_existent()
        assert not workflow.uninitialized

        tags = workflow.get_tags()
        assert "non_existent" in tags
        assert "uninitialized" not in tags

    @pytest.mark.asyncio
    async def test_initialize_callee_node_successful_initialization(self):
        """Test successful workflow initialization through _initialize_callee_node."""
        builder = WorkflowGraphBuilder()
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/valid.yml")

        # Mock successful workflow retrieval
        mock_workflow = MagicMock(spec=Workflow)
        mock_workflow.isInvalid.return_value = False
        mock_workflow.parsed_yml = {"on": ["push"], "env": {"TEST": "value"}}

        mock_api = MagicMock()
        mock_api.retrieve_repo_file = AsyncMock(return_value=mock_workflow)

        with (
            patch.object(builder.graph, "remove_tags_from_node"),
            patch.object(builder.graph, "add_tags_to_node"),
            patch(
                "gatox.caching.cache_manager.CacheManager.get_workflow",
                return_value=None,
            ),
            patch("gatox.caching.cache_manager.CacheManager.set_workflow"),
            patch.object(builder, "build_workflow_jobs", new_callable=AsyncMock),
        ):

            await builder._initialize_callee_node(workflow, mock_api)

        # Verify workflow is properly initialized
        assert not workflow.is_non_existent()
        assert not workflow.uninitialized

        tags = workflow.get_tags()
        assert "initialized" in tags
        assert "non_existent" not in tags
        assert "uninitialized" not in tags


class TestEdgeCasesAndErrorConditions:
    """Test cases for various edge cases and error conditions."""

    def test_workflow_node_state_consistency(self):
        """Test that workflow node states are mutually exclusive."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")

        # Initially uninitialized
        assert workflow.uninitialized
        assert not workflow.non_existent

        # After marking as non-existent
        workflow.mark_as_non_existent()
        assert not workflow.uninitialized
        assert workflow.non_existent

        # Should not be able to be both non-existent and initialized
        # (this would require direct manipulation of internal state)
        workflow.non_existent = False
        mock_workflow_data = MagicMock()
        mock_workflow_data.parsed_yml = {"on": ["push"]}
        workflow.initialize(mock_workflow_data)

        assert not workflow.uninitialized
        assert not workflow.non_existent  # Should be False after initialization

    @pytest.mark.asyncio
    async def test_dfs_with_empty_graph(self):
        """Test DFS behavior with an empty graph."""
        mock_builder = MagicMock()
        graph = TaggedGraph(mock_builder)

        mock_api = MagicMock()

        # Create a single isolated node
        node = WorkflowNode("main", "test/repo", ".github/workflows/isolated.yml")
        node.uninitialized = False
        graph.add_node(node)

        # DFS should return empty since no target tag exists
        paths = await graph.dfs_to_tag(node, "nonexistent_tag", mock_api)
        assert len(paths) == 0

    @pytest.mark.asyncio
    async def test_dfs_with_self_referencing_non_existent_node(self):
        """Test DFS with a non-existent node that has a self-reference."""
        mock_builder = MagicMock()
        mock_builder.initialize_node = AsyncMock()

        graph = TaggedGraph(mock_builder)

        node = WorkflowNode("main", "test/repo", ".github/workflows/self_ref.yml")
        node.mark_as_non_existent()

        graph.add_node(node)
        graph.add_edge(node, node, relation="self_ref")  # Self-reference
        node.extra_tags.add("target")
        graph.add_tag("target", [node])

        mock_api = MagicMock()
        paths = await graph.dfs_to_tag(node, "target", mock_api)

        # Should return empty since DFS stops at non-existent nodes
        assert len(paths) == 0

    def test_workflow_node_hash_and_equality_with_non_existent(self):
        """Test that workflow node hash and equality work with non-existent state."""
        workflow1 = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
        workflow2 = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
        workflow3 = WorkflowNode("main", "test/repo", ".github/workflows/different.yml")

        # Same workflow in different states should still be equal
        workflow1.mark_as_non_existent()
        # workflow2 remains uninitialized

        assert workflow1 == workflow2
        assert hash(workflow1) == hash(workflow2)
        assert workflow1 != workflow3
        assert hash(workflow1) != hash(workflow3)

    def test_workflow_node_get_parts_with_non_existent(self):
        """Test that get_parts() works correctly for non-existent workflows."""
        workflow = WorkflowNode(
            "feature-branch", "owner/repo", ".github/workflows/ci.yml"
        )
        workflow.mark_as_non_existent()

        repo, ref, path = workflow.get_parts()
        assert repo == "owner/repo"
        assert ref == "feature-branch"
        assert path == ".github/workflows/ci.yml"

    def test_workflow_node_attrs_with_non_existent(self):
        """Test that get_attrs() works correctly for non-existent workflows."""
        workflow = WorkflowNode("main", "test/repo", ".github/workflows/test.yml")
        workflow.mark_as_non_existent()

        attrs = workflow.get_attrs()
        assert isinstance(attrs, dict)
        # Should return empty dict as per current implementation
        assert len(attrs) == 0
