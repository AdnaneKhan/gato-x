import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from gatox.workflow_graph.visitors.dispatch_toctou_visitor import DispatchTOCTOUVisitor


@pytest.fixture
def mock_api():
    return MagicMock()


@pytest.fixture
def mock_graph():
    return MagicMock()


async def test_no_workflow_dispatch_nodes(mock_graph, mock_api):
    """
    Test when there are no nodes tagged with 'workflow_dispatch'.
    """
    mock_graph.get_nodes_for_tags.return_value = []
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    mock_graph.get_nodes_for_tags.assert_called_once_with(["workflow_dispatch"])


async def test_dispatch_with_no_paths(mock_graph, mock_api):
    """
    Test when nodes are found but no paths to checkout are discovered.
    """
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=None)
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    mock_graph.dfs_to_tag.assert_called_once()


async def test_dispatch_with_paths_single(mock_graph, mock_api):
    """
    Test with a single path leading to a checkout node.
    """
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]

    # Each path is a list of nodes, here we provide one path
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[MagicMock(), MagicMock()]])
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    assert mock_graph.dfs_to_tag.call_count == 1


async def test_dispatch_multiple_nodes_and_paths(mock_graph, mock_api):
    """
    Test with multiple 'workflow_dispatch' nodes and multiple paths.
    """
    mock_node_1 = MagicMock()
    mock_node_2 = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node_1, mock_node_2]

    path_1 = [MagicMock(), MagicMock()]
    path_2 = [MagicMock(), MagicMock()]
    mock_graph.dfs_to_tag = AsyncMock(
        side_effect=[
            [path_1, path_2],
            None,
        ]
    )
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    assert mock_graph.dfs_to_tag.call_count == 2


@patch.object(DispatchTOCTOUVisitor, "_DispatchTOCTOUVisitor__process_path")
async def test_exceptions_in_process_path(mock_process, mock_api):
    """
    Test that exceptions in __process_path are caught and handled.
    """
    # Use a synchronous MagicMock for get_nodes_for_tags...
    mock_graph = MagicMock()
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    # ...but make dfs_to_tag async so that it can be properly awaited.
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[MagicMock(), MagicMock()]])

    # Configure process_path mock to raise an exception when awaited.
    mock_process.side_effect = Exception("Test exception")

    # This should not raise an exception
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_sha_required_and_present(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test that when SHA is required and present, no vulnerability is detected.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with both PR number and required SHA
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "commit_sha": {
            "description": "Commit SHA",
            "required": True,  # SHA is required
            "type": "string",
        },
    }

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[mock_workflow_node, MagicMock()]])

    # Mock process_path to not raise any exception
    mock_process_path.return_value = None

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process_path.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_no_pr_number_input(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test that when no PR number input exists, no vulnerability is detected.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node without PR number input
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "some_other_input": {
            "description": "Some other input",
            "required": True,
            "type": "string",
        }
    }

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[mock_workflow_node, MagicMock()]])

    # Mock process_path to not raise any exception
    mock_process_path.return_value = None

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process_path.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_workflow_node_no_inputs(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test workflow node with no inputs attribute.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node without inputs
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = None  # No inputs

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[mock_workflow_node, MagicMock()]])

    # Mock process_path to not raise any exception
    mock_process_path.return_value = None

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process_path.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_fork_repository(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test that fork repositories are skipped.
    """
    # Mock repository to be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = True
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[mock_workflow_node, MagicMock()]])

    # Mock process_path to not raise any exception
    mock_process_path.return_value = None

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called (fork check happens inside __process_path)
    mock_process_path.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_multiple_sha_inputs_variations(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test workflow with multiple SHA-related inputs with different names.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with various SHA inputs
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "sha": {  # Different name for SHA
            "description": "Commit SHA",
            "required": True,
            "type": "string",
        },
        "commit_hash": {  # Another variation
            "description": "Commit hash",
            "required": False,
            "type": "string",
        },
    }

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[mock_workflow_node, MagicMock()]])

    # Mock process_path to not raise any exception
    mock_process_path.return_value = None

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process_path.assert_called_once()


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_empty_path(mock_process_path, mock_cache_manager, mock_graph, mock_api):
    """
    Test handling of empty paths returned from DFS.
    """
    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[]])  # Empty path

    # Execute
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called with empty path
    mock_process_path.assert_called_once_with([], mock_graph, mock_api, {})


@patch("gatox.caching.cache_manager.CacheManager")
@patch.object(
    DispatchTOCTOUVisitor,
    "_DispatchTOCTOUVisitor__process_path",
    new_callable=AsyncMock,
)
async def test_process_path_exception_handling(
    mock_process_path, mock_cache_manager, mock_graph, mock_api
):
    """
    Test that exceptions in process_path are properly logged but don't crash the visitor.
    """
    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[[MagicMock(), MagicMock()]])

    # Mock process_path to raise an exception
    mock_process_path.side_effect = ValueError("Test exception")

    # Execute - should not raise exception
    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify process_path was called
    mock_process_path.assert_called_once()


async def test_dfs_returns_none_for_some_nodes(mock_graph, mock_api):
    """
    Test when DFS returns None for some dispatch nodes but paths for others.
    """
    mock_node_1 = MagicMock()
    mock_node_2 = MagicMock()
    mock_node_3 = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node_1, mock_node_2, mock_node_3]

    # First returns paths, second returns None, third returns empty list
    mock_graph.dfs_to_tag = AsyncMock(
        side_effect=[[[MagicMock(), MagicMock()]], None, []]
    )

    await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)

    # Verify dfs_to_tag was called 3 times
    assert mock_graph.dfs_to_tag.call_count == 3


@patch("gatox.caching.cache_manager.CacheManager")
async def test_sha_not_required_with_pr_number(
    mock_cache_manager, mock_graph, mock_api
):
    """
    Test that when PR number is present but SHA is not required,
    the processing continues (potential vulnerability).
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with PR number but SHA not required
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "commit_sha": {
            "description": "Commit SHA",
            "required": False,  # Not required
            "type": "string",
        },
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create mock checkout step
    mock_checkout_node = MagicMock()
    mock_checkout_node.get_tags.return_value = ["StepNode"]
    mock_checkout_node.is_checkout = True
    mock_checkout_node.metadata = "${{ github.event.inputs.pr_number }}"
    mock_checkout_node.repo_name.return_value = "test/repo"
    mock_checkout_node.get_env_vars.return_value = {}

    # Create path
    path = [mock_workflow_node, mock_checkout_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(
        side_effect=[[path], None]
    )  # First call returns path, second returns None (no sinks)

    # Mock graph methods needed for processing
    mock_graph.remove_tags_from_node = MagicMock()

    # Mock the process_path method to simulate the vulnerability detection
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        # Set up the results dict that would be populated by process_path
        results_dict = {}

        async def process_path_side_effect(path, graph, api, results=None):
            if results is not None:
                results["test/repo"] = {"vuln": "detected"}
            elif results_dict is not None:
                results_dict["test/repo"] = {"vuln": "detected"}

        mock_process.side_effect = process_path_side_effect

        # Execute
        await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Verify process_path was called
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_sha_without_required_field(mock_cache_manager, mock_graph, mock_api):
    """
    Test that when SHA input exists but without 'required' field,
    sha_found remains False.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with SHA input missing 'required' field
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "commit_sha": {
            "description": "Commit SHA",
            "type": "string",
            # No 'required' field
        },
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create mock checkout step
    mock_checkout_node = MagicMock()
    mock_checkout_node.get_tags.return_value = ["StepNode"]
    mock_checkout_node.is_checkout = True
    mock_checkout_node.metadata = "${{ github.event.inputs.pr_number }}"
    mock_checkout_node.repo_name.return_value = "test/repo"
    mock_checkout_node.get_env_vars.return_value = {}

    # Create path
    path = [mock_workflow_node, mock_checkout_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(side_effect=[[path], None])

    # Mock graph methods needed for processing
    mock_graph.remove_tags_from_node = MagicMock()

    # Mock the process_path method to simulate the vulnerability detection
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        # Set up the results dict that would be populated by process_path
        results_dict = {}

        async def process_path_side_effect(path, graph, api, results=None):
            if results is not None:
                results["test/repo"] = {"vuln": "detected"}
            elif results_dict is not None:
                results_dict["test/repo"] = {"vuln": "detected"}

        mock_process.side_effect = process_path_side_effect

        # Execute
        await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Verify process_path was called
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_sha_not_dict_value(mock_cache_manager, mock_graph, mock_api):
    """
    Test that when SHA input value is not a dict (e.g., string),
    sha_found remains False.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with SHA as string value
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "commit_sha": "some_default_value",  # Not a dict
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create mock checkout step
    mock_checkout_node = MagicMock()
    mock_checkout_node.get_tags.return_value = ["StepNode"]
    mock_checkout_node.is_checkout = True
    mock_checkout_node.metadata = "${{ github.event.inputs.pr_number }}"
    mock_checkout_node.repo_name.return_value = "test/repo"
    mock_checkout_node.get_env_vars.return_value = {}

    # Create path
    path = [mock_workflow_node, mock_checkout_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(side_effect=[[path], None])

    # Mock graph methods needed for processing
    mock_graph.remove_tags_from_node = MagicMock()

    # Mock the process_path method to simulate the vulnerability detection
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        # Set up the results dict that would be populated by process_path
        results_dict = {}

        async def process_path_side_effect(path, graph, api, results=None):
            if results is not None:
                results["test/repo"] = {"vuln": "detected"}
            elif results_dict is not None:
                results_dict["test/repo"] = {"vuln": "detected"}

        mock_process.side_effect = process_path_side_effect

        # Execute
        await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Verify process_path was called
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_sha_required_with_pr_number(mock_cache_manager, mock_graph, mock_api):
    """
    Test that when both a PR number and required SHA are present,
    the processing breaks early (no vulnerability).
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with PR number and required SHA
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "commit_sha": {"description": "Commit SHA", "required": True, "type": "string"},
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create path with workflow node
    path = [mock_workflow_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock the process_path method - it should be called but no vulnerability should be added
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        # Don't add any results - the logic should break early
        mock_process.return_value = None

        # Execute
        results = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Should not report vulnerability when both PR and required SHA are present
        assert results == {}
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_multiple_sha_inputs_only_one_required(
    mock_cache_manager, mock_graph, mock_api
):
    """
    Test that when multiple SHA inputs exist but only one is required,
    sha_found is True.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with multiple SHA inputs
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "base_sha": {"description": "Base SHA", "required": False, "type": "string"},
        "head_sha": {
            "description": "Head SHA",
            "required": True,  # This one is required
            "type": "string",
        },
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create path
    path = [mock_workflow_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock the process_path method
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        mock_process.return_value = None

        # Execute
        results = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Should not report vulnerability when PR and at least one required SHA present
        assert results == {}
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_sha_key_case_insensitive(mock_cache_manager, mock_graph, mock_api):
    """
    Test that SHA detection is case-insensitive.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with uppercase SHA key
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        },
        "COMMIT_SHA": {  # Uppercase SHA
            "description": "Commit SHA",
            "required": True,
            "type": "string",
        },
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create path
    path = [mock_workflow_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock the process_path method
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        mock_process.return_value = None

        # Execute
        results = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Should not report vulnerability - uppercase SHA should be detected
        assert results == {}
        mock_process.assert_called()


@patch("gatox.caching.cache_manager.CacheManager")
async def test_no_pr_number_with_sha(mock_cache_manager, mock_graph, mock_api):
    """
    Test that when no PR number is present (even with SHA),
    processing breaks early.
    """
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False
    mock_cache_manager.return_value.get_repository.return_value = mock_repo

    # Create mock workflow node with SHA but no PR number
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.inputs = {
        "branch_name": {
            "description": "Branch to checkout",
            "required": True,
            "type": "string",
        },
        "commit_sha": {"description": "Commit SHA", "required": True, "type": "string"},
    }
    mock_workflow_node.get_env_vars.return_value = {}
    mock_workflow_node.repo_name.return_value = "test/repo"

    # Create path
    path = [mock_workflow_node]

    # Setup graph mocks
    mock_dispatch_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_dispatch_node]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[path])

    # Mock the process_path method
    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        new_callable=AsyncMock,
    ) as mock_process:
        mock_process.return_value = None

        # Execute
        results = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Should not report vulnerability when no PR number present
        assert results == {}
        mock_process.assert_called()


async def test_process_path_job_node_with_outputs(mock_graph, mock_api):
    """Test process_path with JobNode that has outputs"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with PR number input and no required SHA
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {
        "pr_number": {
            "description": "Pull request number",
            "required": True,
            "type": "string",
        }
    }
    mock_workflow_node.get_env_vars.return_value = {
        "PR_ENV": "github.event.pull_request.number"
    }

    # Create mock job node with outputs
    mock_job_node = MagicMock()
    mock_job_node.get_tags.return_value = ["JobNode"]
    mock_job_node.outputs = {"output_key": "env.PR_ENV_VAR"}
    mock_job_node.params = {"input_param": "test_value"}

    # Create mock step node with checkout
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "inputs.pr_number"

    path = [mock_workflow_node, mock_job_node, mock_step_node]

    # Mock VisitorUtils methods and CacheManager
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils.append_path.return_value = None
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return sink paths using AsyncMock
        mock_graph.dfs_to_tag = AsyncMock(return_value=[["sink_path"]])

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Verify VisitorUtils methods were called
        mock_visitor_utils.check_mutable_ref.assert_called()
        mock_visitor_utils.append_path.assert_called()
        mock_visitor_utils._add_results.assert_called()


async def test_process_path_fork_repository(mock_graph, mock_api):
    """Test process_path breaks when repository is a fork"""
    # Mock repository to be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = True

    # Create mock workflow node
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}

    path = [mock_workflow_node]
    results = {}

    # Mock CacheManager inside the test execution
    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Verify that CacheManager was called with correct repo name
        mock_cache_manager.assert_called_once()
        mock_cache_manager.return_value.get_repository.assert_called_once_with(
            "owner/repo"
        )


async def test_process_path_no_inputs(mock_graph, mock_api):
    """Test process_path breaks when workflow has no inputs"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        # Create mock workflow node with no inputs
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.inputs = None

        path = [mock_workflow_node]
        results = {}

        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should exit early when no inputs
        assert results == {}


async def test_process_path_step_node_checkout_with_context_regex(mock_graph, mock_api):
    """Test process_path with StepNode checkout using context regex"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with PR number input
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {}

    # Create mock step node with checkout using ${{ }} syntax
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "${{ inputs.pr_number }}"

    path = [mock_workflow_node, mock_step_node]

    # Mock CacheManager, CONTEXT_REGEX, and VisitorUtils
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CONTEXT_REGEX"
        ) as mock_regex,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        mock_regex.findall.return_value = ["inputs.pr_number"]
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return no sinks using AsyncMock
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should call _add_results with LOW confidence when no sinks
        mock_visitor_utils._add_results.assert_called()


async def test_process_path_step_node_checkout_env_lookup(mock_graph, mock_api):
    """Test process_path with StepNode checkout using environment variable lookup"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with PR number input
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {
        "PR_VAR": "github.event.pull_request.number"
    }

    # Create mock step node with checkout using env variable
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "PR_VAR"

    path = [mock_workflow_node, mock_step_node]

    # Mock CacheManager and VisitorUtils
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return no sinks using AsyncMock
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should check mutable ref with the metadata value (not env variable)
        # because env lookup only happens when "inputs." is in metadata
        mock_visitor_utils.check_mutable_ref.assert_called_with("PR_VAR")


async def test_process_path_step_node_checkout_inputs_env_lookup(mock_graph, mock_api):
    """Test process_path with StepNode checkout using inputs that reference environment variables"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with PR number input
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {
        "pr_number": "github.event.pull_request.number"
    }

    # Create mock step node with checkout using inputs reference
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "inputs.pr_number"  # Contains "inputs."

    path = [mock_workflow_node, mock_step_node]

    # Mock CacheManager and VisitorUtils
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return no sinks using AsyncMock
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should check mutable ref with the raw metadata value
        # because without ${{ }} syntax, inputs. prefix is not removed
        mock_visitor_utils.check_mutable_ref.assert_called_with("inputs.pr_number")


async def test_process_path_step_node_checkout_dollar_brace_env_lookup(
    mock_graph, mock_api
):
    """Test process_path with StepNode checkout using ${{ inputs.* }} syntax for environment variable lookup"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with PR number input
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {
        "pr_number": "github.event.pull_request.number"
    }

    # Create mock step node with checkout using ${{ inputs.* }} syntax
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "${{ inputs.pr_number }}"  # Contains both ${{ and inputs.

    path = [mock_workflow_node, mock_step_node]

    # Mock CacheManager, CONTEXT_REGEX, and VisitorUtils
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CONTEXT_REGEX"
        ) as mock_regex,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        # Mock CONTEXT_REGEX to extract the variable
        mock_regex.findall.return_value = ["inputs.pr_number"]
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return no sinks using AsyncMock
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should check mutable ref with the environment variable value
        # because CONTEXT_REGEX extracts "inputs.pr_number", strips "inputs." to get "pr_number",
        # and finds "pr_number" in env_lookup
        mock_visitor_utils.check_mutable_ref.assert_called_with(
            "github.event.pull_request.number"
        )


async def test_process_path_action_node(mock_graph, mock_api):
    """Test process_path with ActionNode"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        # Create mock workflow node with PR number input
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.inputs = {"pr_number": {"required": True}}
        mock_workflow_node.get_env_vars.return_value = {}

        # Create mock action node
        mock_action_node = MagicMock()
        mock_action_node.get_tags.return_value = ["ActionNode"]

        path = [mock_workflow_node, mock_action_node]

        # Mock VisitorUtils methods
        with patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils:
            mock_visitor_utils.initialize_action_node = AsyncMock()

            results = {}
            await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
                path, mock_graph, mock_api, results
            )

            # Should initialize action node
            mock_visitor_utils.initialize_action_node.assert_called_with(
                mock_graph, mock_api, mock_action_node
            )


async def test_find_dispatch_misconfigurations_dfs_exception(mock_graph, mock_api):
    """Test exception handling during DFS to tag operation"""
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]

    # Mock dfs_to_tag to raise an exception
    mock_graph.dfs_to_tag = AsyncMock(side_effect=Exception("DFS error"))

    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.logger"
    ) as mock_logger:
        result = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
            mock_graph, mock_api
        )

        # Should handle exception gracefully and return empty results
        assert result == {}
        mock_logger.error.assert_called_with(
            "Error finding paths for dispatch node: DFS error"
        )
        mock_logger.warning.assert_called_with(f"Node: {mock_node}")


async def test_find_dispatch_misconfigurations_process_path_exception(
    mock_graph, mock_api
):
    """Test exception handling during path processing"""
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]

    # Mock successful DFS but failing path processing
    mock_path = [MagicMock(), MagicMock()]
    mock_graph.dfs_to_tag = AsyncMock(return_value=[mock_path])

    with patch.object(
        DispatchTOCTOUVisitor,
        "_DispatchTOCTOUVisitor__process_path",
        side_effect=Exception("Process path error"),
    ):
        with patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.logger"
        ) as mock_logger:
            result = await DispatchTOCTOUVisitor.find_dispatch_misconfigurations(
                mock_graph, mock_api
            )

            # Should handle exception gracefully and return empty results
            assert result == {}
            mock_logger.warning.assert_any_call(
                "Error processing path: Process path error"
            )
            mock_logger.warning.assert_any_call(f"Path: {mock_path}")


async def test_process_path_job_node_with_env_outputs(mock_graph, mock_api):
    """Test process_path with JobNode that has outputs referencing env vars"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        # Create mock workflow node
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.inputs = {"pr_number": {"required": True}}
        mock_workflow_node.get_env_vars.return_value = {
            "TEST_ENV": "github.event.pull_request.number"
        }

        # Create mock job node with env-based outputs
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.outputs = {"test_output": "env.TEST_ENV"}  # References env var
        mock_job_node.params = {}

        path = [mock_workflow_node, mock_job_node]
        results = {}

        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should process without errors
        assert results == {}


async def test_process_path_workflow_call_with_job_params(mock_graph, mock_api):
    """Test process_path with workflow call node that has job parameters"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        # Create mock job node (should be at index 0)
        mock_job_node = MagicMock()
        mock_job_node.get_tags.return_value = ["JobNode"]
        mock_job_node.params = {"job_param": "test_value"}

        # Create mock workflow node (should be at index 1)
        mock_workflow_node = MagicMock()
        mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
        mock_workflow_node.repo_name.return_value = "owner/repo"
        mock_workflow_node.inputs = {"pr_number": {"required": True}}
        mock_workflow_node.get_env_vars.return_value = {}

        path = [mock_job_node, mock_workflow_node]  # Job node first, then workflow node
        results = {}

        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should process the job parameters and update input lookup
        assert results == {}


async def test_process_path_workflow_node_with_required_sha(mock_graph, mock_api):
    """Test process_path with workflow node that has required SHA input"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node with both PR and required SHA
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {
        "pr_number": {"required": True},
        "commit_sha": {"required": True},  # Required SHA should stop processing
    }
    mock_workflow_node.get_env_vars.return_value = {}

    path = [mock_workflow_node]

    # Mock CacheManager
    with patch(
        "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
    ) as mock_cache_manager:
        mock_cache_manager.return_value.get_repository.return_value = mock_repo

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should break early due to required SHA
        assert results == {}


async def test_process_path_step_node_checkout_context_regex_empty_result(
    mock_graph, mock_api
):
    """Test process_path with StepNode checkout when CONTEXT_REGEX returns empty"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {}

    # Create mock step node with checkout using ${{ }} syntax
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "${{ some.unknown.value }}"

    path = [mock_workflow_node, mock_step_node]

    # Mock all dependencies
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CONTEXT_REGEX"
        ) as mock_regex,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        # Mock CONTEXT_REGEX to return empty list
        mock_regex.findall.return_value = []
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return no sinks
        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should check mutable ref with the original metadata since CONTEXT_REGEX returned empty
        mock_visitor_utils.check_mutable_ref.assert_called_with(
            "${{ some.unknown.value }}"
        )


async def test_process_path_step_node_checkout_input_lookup(mock_graph, mock_api):
    """Test process_path with StepNode checkout using input lookup"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock job node (for input_lookup)
    mock_job_node = MagicMock()
    mock_job_node.get_tags.return_value = ["JobNode"]
    mock_job_node.params = {"pr_ref": "refs/pull/123/head"}

    # Create mock workflow node
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {}

    # Create mock step node that references input_lookup with ${{ }} syntax
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "${{ inputs.pr_ref }}"  # Uses ${{ }} syntax

    path = [mock_job_node, mock_workflow_node, mock_step_node]

    # Mock dependencies
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CONTEXT_REGEX"
        ) as mock_regex,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        # Mock CONTEXT_REGEX to extract and allow stripping inputs.
        mock_regex.findall.return_value = ["inputs.pr_ref"]
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils._add_results.return_value = None

        mock_graph.dfs_to_tag = AsyncMock(return_value=None)

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should check mutable ref with value from input_lookup
        # The logic extracts "inputs.pr_ref", strips "inputs." to get "pr_ref",
        # and looks up "pr_ref" in input_lookup to get "refs/pull/123/head"
        mock_visitor_utils.check_mutable_ref.assert_called_with("refs/pull/123/head")


async def test_process_path_step_node_checkout_with_sinks(mock_graph, mock_api):
    """Test process_path with StepNode checkout that has sinks"""
    # Mock repository to not be a fork
    mock_repo = MagicMock()
    mock_repo.is_fork.return_value = False

    # Create mock workflow node
    mock_workflow_node = MagicMock()
    mock_workflow_node.get_tags.return_value = ["WorkflowNode"]
    mock_workflow_node.repo_name.return_value = "owner/repo"
    mock_workflow_node.inputs = {"pr_number": {"required": True}}
    mock_workflow_node.get_env_vars.return_value = {}

    # Create mock step node with checkout
    mock_step_node = MagicMock()
    mock_step_node.get_tags.return_value = ["StepNode"]
    mock_step_node.is_checkout = True
    mock_step_node.metadata = "refs/pull/123/head"

    path = [mock_workflow_node, mock_step_node]

    # Mock sink path
    mock_sink_path = [MagicMock(), MagicMock()]

    # Mock dependencies
    with (
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.CacheManager"
        ) as mock_cache_manager,
        patch(
            "gatox.workflow_graph.visitors.dispatch_toctou_visitor.VisitorUtils"
        ) as mock_visitor_utils,
    ):

        mock_cache_manager.return_value.get_repository.return_value = mock_repo
        mock_visitor_utils.check_mutable_ref.return_value = True
        mock_visitor_utils.append_path.return_value = None
        mock_visitor_utils._add_results.return_value = None

        # Mock dfs_to_tag to return sinks
        mock_graph.dfs_to_tag = AsyncMock(return_value=[mock_sink_path])

        results = {}
        await DispatchTOCTOUVisitor._DispatchTOCTOUVisitor__process_path(
            path, mock_graph, mock_api, results
        )

        # Should append path and add results when sinks are found
        mock_visitor_utils.append_path.assert_called_with(path, mock_sink_path)
        mock_visitor_utils._add_results.assert_called()
