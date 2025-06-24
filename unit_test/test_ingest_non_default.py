import pytest
from unittest.mock import MagicMock, patch

from gatox.enumerate.deep_dive.ingest_non_default import IngestNonDefault
from unittest.mock import AsyncMock
import asyncio

from gatox.models.repository import Repository


@pytest.fixture
def mock_repo():
    repo = MagicMock(spec=Repository)
    repo.name = "test/repo"
    return repo


@pytest.fixture
def mock_api():
    api = MagicMock()
    api.pat = "test_pat"
    return api


async def test_ingest_new_api(mock_repo, mock_api):
    IngestNonDefault._tasks = []
    IngestNonDefault._api = None

    task = await IngestNonDefault.ingest(mock_repo, mock_api)

    assert isinstance(task, asyncio.Task)
    assert IngestNonDefault._api == mock_api
    assert len(IngestNonDefault._tasks) == 1
    assert task in IngestNonDefault._tasks


async def test_ingest_existing_api(mock_repo, mock_api):
    IngestNonDefault._tasks = []
    IngestNonDefault._api = mock_api

    task = await IngestNonDefault.ingest(mock_repo, mock_api)

    assert isinstance(task, asyncio.Task)
    assert len(IngestNonDefault._tasks) == 1
    assert task in IngestNonDefault._tasks


@patch("gatox.enumerate.deep_dive.ingest_non_default.Git")
@patch("gatox.enumerate.deep_dive.ingest_non_default.WorkflowGraphBuilder")
async def test_process_repo_empty_workflows(
    mock_builder, mock_git, mock_repo, mock_api
):
    mock_git_instance = AsyncMock()
    mock_git_instance.get_non_default.return_value = []
    mock_git.return_value = mock_git_instance

    IngestNonDefault._api = mock_api
    await IngestNonDefault._process_repo(mock_repo)

    mock_git.assert_called_once_with(mock_api.pat, mock_repo.name)
    mock_git_instance.get_non_default.assert_called_once()
    mock_builder.return_value.build_graph_from_yaml.assert_not_called()


@patch("gatox.enumerate.deep_dive.ingest_non_default.Git")
@patch("gatox.enumerate.deep_dive.ingest_non_default.WorkflowGraphBuilder")
async def test_process_repo_multiple_workflows(
    mock_builder, mock_git, mock_repo, mock_api
):
    mock_workflows = [MagicMock(), MagicMock()]
    mock_git_instance = AsyncMock()
    mock_git_instance.get_non_default.return_value = mock_workflows
    mock_git.return_value = mock_git_instance

    mock_builder_instance = AsyncMock()
    mock_builder.return_value = mock_builder_instance

    IngestNonDefault._api = mock_api
    await IngestNonDefault._process_repo(mock_repo)

    assert mock_builder_instance.build_graph_from_yaml.call_count == 2
    mock_builder_instance.build_graph_from_yaml.assert_any_call(
        mock_workflows[0], mock_repo
    )
    mock_builder_instance.build_graph_from_yaml.assert_any_call(
        mock_workflows[1], mock_repo
    )


async def test_pool_empty_no_tasks():
    IngestNonDefault._tasks = []

    result = await IngestNonDefault.pool_empty()

    assert result is None


async def test_pool_empty_with_tasks():
    IngestNonDefault._tasks = []

    result = await IngestNonDefault.pool_empty()

    assert result is None
    assert len(IngestNonDefault._tasks) == 0


@patch("gatox.enumerate.deep_dive.ingest_non_default.Git")
async def test_process_repo_handles_exception(mock_git, mock_repo, mock_api):
    mock_git_instance = AsyncMock()
    mock_git_instance.get_non_default.side_effect = Exception("Test error")
    mock_git.return_value = mock_git_instance

    IngestNonDefault._api = mock_api

    with pytest.raises(Exception, match="Test error"):
        await IngestNonDefault._process_repo(mock_repo)
