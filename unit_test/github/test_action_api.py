"""Tests for :class:`gatox.github.action_api.ActionApi`.

Carved out of ``unit_test/test_api.py`` after the api split (#144).
The pre-split monolithic file lives on at the same path and now only
keeps the lifecycle/init tests; per-sub-API tests moved here.
"""

import logging
import os
import pathlib
from unittest.mock import AsyncMock, MagicMock, patch

from gatox.cli.output import Output
from gatox.github.api import Api

logging.root.setLevel(logging.DEBUG)

output = Output(False)


async def test_check_repo_runners():
    """Test method to retrieve runners from a repo."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    runner_list = [
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
        {"runnerinfo": "test"},
    ]
    mock_response.json.return_value = {"runners": runner_list}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.action.get_repo_runners("testOrg/TestRepo")

    assert result == runner_list

    mock_response.status_code = 401

    result = await abstraction_layer.action.get_repo_runners("testOrg/TestRepo")
    assert not result


async def test_retrieve_run_logs():
    """Test retrieving run logs."""
    curr_path = pathlib.Path(__file__).parent.parent.resolve()
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    mock_response.json.return_value = {
        "workflow_runs": [
            {
                "id": 123,
                "run_attempt": 1,
                "conclusion": "success",
                "head_branch": "dev",
                "path": ".github/workflows/build.yml@dev",
            }
        ]
    }

    with open(os.path.join(curr_path, "files/run_log.zip"), "rb") as run_log:
        zip_bytes = run_log.read()
        mock_response.content = zip_bytes

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    logs = await abstraction_layer.action.retrieve_run_logs(
        "testOrg/testRepo", workflows=["build.yml"]
    )

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"

    logs = await abstraction_layer.action.retrieve_run_logs(
        "testOrg/testRepo", workflows=["build.yml"]
    )

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"


async def test_parse_wf_runs():
    """Test retrieving wf run count."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    mock_response.json.return_value = {"total_count": 2}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    wf_count = await abstraction_layer.action.parse_workflow_runs("testOrg/testRepo")

    assert wf_count == 2


async def test_parse_wf_runs_fail():
    """Test 403 code when retrieving wf run count"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    wf_count = await abstraction_layer.action.parse_workflow_runs("testOrg/testRepo")

    assert wf_count is None


async def test_get_recent_workflow():
    """Test retrieving a recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "total_count": 1,
        "workflow_runs": [{"id": 15, "path": ".github/workflows/testwf.yml@main"}],
    }

    api = Api(test_pat, "2022-11-28", client=mock_client)
    workflow_id = await api.action.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == 15


async def test_get_recent_workflow_missing():
    """Test retrieving a missing recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "total_count": 0,
        "workflow_runs": [],
        "path": ".github/workflows/testwf.yml@main",
    }

    api = Api(test_pat, "2022-11-28", client=mock_client)
    workflow_id = await api.action.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == 0


async def test_get_recent_workflow_fail():
    """Test failing the retrieval of a recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    workflow_id = await api.action.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == -1


async def test_get_workflow_status_queued():
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "queued"}

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.action.get_workflow_status("repo", 5) == 0


async def test_get_workflow_status_failed():
    """Test retrieving the status of a workflow."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "status": "completed",
        "conclusion": "failure",
    }

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.action.get_workflow_status("repo", 5) == -1


async def test_get_workflow_status_errorr():
    """Test retrieving the status of a workflow with error."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.action.get_workflow_status("repo", 5) == -1


async def test_delete_workflow_fail():
    """Test deleting a workflow run failure."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert not await api.action.delete_workflow_run("repo", 5)


@patch("gatox.github.action_api.open")
async def test_download_workflow_success(mock_open):
    """Test downloading workflow logs successfully."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.action.download_workflow_logs("repo", 5)


@patch("gatox.github.action_api.open")
async def test_download_workflow_fail(mock_open):
    """Test downloading workflow logs failure."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert not await api.action.download_workflow_logs("repo", 5)
