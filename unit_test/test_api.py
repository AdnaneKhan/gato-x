import base64
import os
import pytest
import pathlib
import logging

from unittest.mock import AsyncMock, MagicMock, patch

from gatox.github.api import Api
from gatox.cli.output import Output

logging.root.setLevel(logging.DEBUG)

output = Output(False)


def test_initialize():
    """Test initialization of API abstraction layer."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28")

    assert abstraction_layer.pat == test_pat
    assert abstraction_layer.verify_ssl is True


def test_socks():
    """Test that we can successfully configure a SOCKS proxy."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28", socks_proxy="localhost:9090")

    assert abstraction_layer.transport == "socks5://localhost:9090"


def test_http_proxy():
    """Test that we can successfully configure an HTTP proxy."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    abstraction_layer = Api(test_pat, "2022-11-28", http_proxy="localhost:1080")

    assert abstraction_layer.transport == "http://localhost:1080"


async def test_user_scopes():
    """Check user."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    mock_response = MagicMock()
    mock_response.headers.get.return_value = "repo, admin:org"
    mock_response.json.return_value = {
        "login": "TestUserName",
        "name": "TestUser",
    }
    mock_response.status_code = 200
    mock_client = AsyncMock()

    mock_client.get.return_value = mock_response

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    user_info = await abstraction_layer.check_user()

    assert user_info["user"] == "TestUserName"
    assert "repo" in user_info["scopes"]


def test_socks_and_http():
    """Test initializing API abstraction layer with SOCKS and HTTP proxy,
    which should raise a valueerror.
    """
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    with pytest.raises(ValueError):
        Api(
            test_pat,
            "2022-11-28",
            socks_proxy="localhost:1090",
            http_proxy="localhost:8080",
        )


async def test_validate_sso():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()

    mock_response.status_code = 200

    mock_client.get.return_value = mock_response
    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    res = await abstraction_layer.validate_sso("testorg", "testRepo")

    assert res is True


async def test_validate_sso_fail():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()

    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    res = await abstraction_layer.validate_sso("testorg", "testRepo")

    assert res is False


async def test_invalid_pat():
    """Test calling a request with an invalid PAT"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    assert await abstraction_layer.check_user() is None


async def test_delete_repo():
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 204

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is True


async def test_delete_fail():
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.delete_repository("testOrg/TestRepo")

    assert result is False


async def test_fork_repository():
    """Test fork repo happy path"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 202
    mock_response.json.return_value = {"full_name": "myusername/TestRepo"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.fork_repository("testOrg/TestRepo")

    assert result == "myusername/TestRepo"


async def test_fork_repository_forbid():
    """Test repo fork forbidden."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 403
    mock_response.json.return_value = {"full_name": "myusername/TestRepo"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


async def test_fork_repository_notfound():
    """Test repo fork 404."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 404
    mock_response.json.return_value = {"full_name": "myusername/TestRepo"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


async def test_fork_repository_fail():
    """Test repo fork failure"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 422
    mock_response.json.return_value = {"full_name": "myusername/TestRepo"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.fork_repository("testOrg/TestRepo")
    assert result is False


async def test_fork_pr():
    """Test creating a fork PR"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 201
    mock_response.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result == "https://github.com/testOrg/testRepo/pull/11"


async def test_fork_pr_failed():
    """Test creating a fork PR"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.post.return_value = mock_response
    mock_response.status_code = 401
    mock_response.json.return_value = {
        "html_url": "https://github.com/testOrg/testRepo/pull/11"
    }

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.create_fork_pr(
        "testOrg/testRepo", "testuser", "badBranch", "develop", "Test PR Title"
    )

    assert result is None


async def test_get_repo():
    """Test getting repo info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"repo1": "fakerepodata"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.get_repository("testOrg/TestRepo")

    assert result["repo1"] == "fakerepodata"


async def test_get_org():
    """Test retrievign org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"org1": "fakeorgdata"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.get_organization_details("testOrg")

    assert result["org1"] == "fakeorgdata"


async def test_get_org_notfound():
    """Test 404 code when retrieving org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 404

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.get_organization_details("testOrg")

    assert result is None


async def test_check_org_runners():
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"total_count": 5}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.check_org_runners("testOrg")

    assert result == {"total_count": 5}


async def test_check_org_runners_fail():
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.check_org_runners("testOrg")

    assert result is None


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
    result = await abstraction_layer.get_repo_runners("testOrg/TestRepo")

    assert result == runner_list

    mock_response.status_code = 401

    result = await abstraction_layer.get_repo_runners("testOrg/TestRepo")
    assert not result


async def test_check_org_repos_invalid():
    """Test method to retrieve repos from org with an invalid type."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    with pytest.raises(ValueError):
        await abstraction_layer.check_org_repos("testOrg", "invalid")


async def test_check_org_repos():
    """Test method to retrieve repos from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {"repo1": "fakerepodata", "archived": False},
        {"repo2": "fakerepodata", "archived": False},
        {"repo3": "fakerepodata", "archived": False},
        {"repo4": "fakerepodata", "archived": False},
        {"repo5": "fakerepodata", "archived": False},
    ]

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.check_org_repos("testOrg", "internal")

    assert len(result) == 5


async def test_check_org():
    """Test method to retrieve orgs."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    MagicMock()
    mock_client.get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[
                    {"login": "org1"},
                    {"login": "org2"},
                    {"login": "org3"},
                    {"login": "org4"},
                    {"login": "org5"},
                ]
            ),
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(return_value=[]),
        ),
    ]

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.check_organizations()

    assert len(result) == 5
    assert result[0] == "org1"
    assert result[1] == "org2"
    assert result[2] == "org3"
    assert result[3] == "org4"
    assert result[4] == "org5"


async def test_retrieve_run_logs():
    """Test retrieving run logs."""
    curr_path = pathlib.Path(__file__).parent.resolve()
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
    logs = await abstraction_layer.retrieve_run_logs(
        "testOrg/testRepo", workflows=["build.yml"]
    )

    assert len(logs) == 1
    assert list(logs)[0]["runner_name"] == "runner-30"

    logs = await abstraction_layer.retrieve_run_logs(
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
    wf_count = await abstraction_layer.parse_workflow_runs("testOrg/testRepo")

    assert wf_count == 2


async def test_parse_wf_runs_fail():
    """Test 403 code when retrieving wf run count"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    wf_count = await abstraction_layer.parse_workflow_runs("testOrg/testRepo")

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
    workflow_id = await api.get_recent_workflow("repo", "sha", "testwf")

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
    workflow_id = await api.get_recent_workflow("repo", "sha", "testwf")

    assert workflow_id == 0


async def test_get_recent_workflow_fail():
    """Test failing the retrieval of a recent workflow by sha."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    workflow_id = await api.get_recent_workflow("repo", "sha", "testwf")

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
    assert await api.get_workflow_status("repo", 5) == 0


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
    assert await api.get_workflow_status("repo", 5) == -1


async def test_get_workflow_status_errorr():
    """Test retrieving the status of a workflow with error."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.get_workflow_status("repo", 5) == -1


async def test_delete_workflow_fail():
    """Test deleting a workflow run failure."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert not await api.delete_workflow_run("repo", 5)


@patch("gatox.github.api.open")
async def test_download_workflow_success(mock_open):
    """Test downloading workflow logs successfully."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.download_workflow_logs("repo", 5)


@patch("gatox.github.api.open")
async def test_download_workflow_fail(mock_open):
    """Test downloading workflow logs failure."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert not await api.download_workflow_logs("repo", 5)


async def test_get_repo_branch():
    """Test retrieving the existence of a branch."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.get_repo_branch("repo", "branch") == 1

    mock_response.status_code = 404
    assert await api.get_repo_branch("repo", "branch") == 0

    mock_response.status_code = 401
    assert await api.get_repo_branch("repo", "branch") == -1


async def test_create_branch():
    """Test creating a new branch"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.side_effect = [
        {"default_branch": "dev"},
        {
            "ref": "refs/heads/dev",
            "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
            "object": {
                "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                "type": "commit",
                "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
            },
        },
    ]

    mock_post_response = MagicMock()
    mock_post_response.status_code = 201
    mock_client.post.return_value = mock_post_response

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.create_branch("test_repo", "abcdefg") is True


async def test_create_branch_fail():
    """Test creating a new branch failure"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.side_effect = [
        {"default_branch": "dev"},
        {
            "ref": "refs/heads/dev",
            "node_id": "REF_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "url": "https://api.github.com/repos/testOrg/testRepo/git/refs/heads/dev",
            "object": {
                "sha": "988881adc9fc3655077dc2d4d757d480b5ea0e11",
                "type": "commit",
                "url": "https://api.github.com/repos/praetorian-inc/testOrg/commits/988881adc9fc3655077dc2d4d757d480b5ea0e11",
            },
        },
    ]

    mock_post_response = MagicMock()
    mock_post_response.status_code = 422
    mock_client.post.return_value = mock_post_response

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.create_branch("test_repo", "abcasync defg") is False


async def test_delete_branch():
    """Test deleting branch"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 204

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.delete_branch("testRepo", "testBranch")


async def test_commit_file():
    """Test commiting a file"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    test_filedata = b"foobarbaz"
    test_sha = "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"

    mock_response = MagicMock()
    mock_client.put.return_value = mock_response
    mock_response.status_code = 201
    mock_response.json.return_value = {"commit": {"sha": test_sha}}

    api = Api(test_pat, "2022-11-28", client=mock_client)

    commit_sha = await api.commit_file(
        "testOrg/testRepo",
        "testBranch",
        "test/newFile",
        test_filedata,
        commit_author="testUser",
        commit_email="testemail@example.org",
    )

    assert commit_sha == test_sha


async def test_workflow_ymls():
    """Test retrieving workflow yml files using the API."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    test_return = [
        {
            "name": "integration.yaml",
            "path": ".github/workflows/integration.yaml",
            "sha": "a38970d0b6a86e1ac108854979d47ec412789708",
            "size": 2095,
            "url": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
            "html_url": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            "git_url": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
            "download_url": "https://raw.githubusercontent.com/praetorian-inc/gato/main/.github/workflows/integration.yaml",
            "type": "file",
            "_links": {
                "self": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
                "git": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
                "html": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            },
        }
    ]

    base64_enc = base64.b64encode(b"FooBarBaz")
    test_file_content = {"content": base64_enc}

    mock_response = MagicMock()
    mock_client.get.side_effect = [mock_response, mock_response]
    mock_response.status_code = 200
    mock_response.json.side_effect = [test_return, test_file_content]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    ymls = await api.retrieve_workflow_ymls("testOrg/testRepo")

    assert len(ymls) == 1
    assert ymls[0].workflow_name == "integration.yaml"
    assert ymls[0].workflow_contents == "FooBarBaz"


async def test_workflow_ymls_ref():
    """Test retrieving workflow yml files from a specific ref."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    test_return = [
        {
            "name": "integration.yaml",
            "path": ".github/workflows/integration.yaml",
            "sha": "a38970d0b6a86e1ac108854979d47ec412789708",
            "size": 2095,
            "url": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
            "html_url": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            "git_url": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
            "download_url": "https://raw.githubusercontent.com/praetorian-inc/gato/main/.github/workflows/integration.yaml",
            "type": "file",
            "_links": {
                "self": "https://api.github.com/repos/praetorian-inc/gato/contents/.github/workflows/integration.yaml?ref=main",
                "git": "https://api.github.com/repos/praetorian-inc/gato/git/blobs/a38970d0b6a86e1ac108854979d47ec412789708",
                "html": "https://github.com/praetorian-inc/gato/blob/main/.github/workflows/integration.yaml",
            },
        }
    ]

    base64_enc = base64.b64encode(b"FooBarBaz")
    test_file_content = {"content": base64_enc}

    mock_response = MagicMock()
    mock_client.get.side_effect = [mock_response, mock_response]
    mock_response.status_code = 200
    mock_response.json.side_effect = [test_return, test_file_content]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    ymls = await api.retrieve_workflow_ymls_ref("testOrg/testRepo", sha)

    assert len(ymls) == 1
    assert ymls[0].workflow_name == "integration.yaml"
    assert ymls[0].workflow_contents == "FooBarBaz"


async def test_get_secrets():
    """Test getting repo secret names."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "total_count": 3,
        "secrets": [{}, {}, {}],
    }

    api = Api(test_pat, "2022-11-28", client=mock_client)
    secrets = await api.get_secrets("testOrg/testRepo")

    assert len(secrets) == 3


async def test_get_org_secrets():
    """Tests getting org secrets"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.side_effect = [
        {
            "total_count": 2,
            "secrets": [
                {
                    "name": "DEPLOY_TOKEN",
                    "created_at": "2019-08-10T14:59:22Z",
                    "updated_at": "2020-01-10T14:59:22Z",
                    "visibility": "all",
                },
                {
                    "name": "GH_TOKEN",
                    "created_at": "2019-08-10T14:59:22Z",
                    "updated_at": "2020-01-10T14:59:22Z",
                    "visibility": "selected",
                    "selected_repositories_url": "https://api.github.com/orgs/testOrg/actions/secrets/GH_TOKEN/repositories",
                },
            ],
        },
        {
            "total_count": 2,
            "repositories": [
                {"full_name": "testOrg/testRepo1"},
                {"full_name": "testOrg/testRepo2"},
            ],
        },
    ]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    secrets = await api.get_org_secrets("testOrg")

    assert len(secrets) == 2
    assert secrets[0]["name"] == "DEPLOY_TOKEN"
    assert secrets[1]["name"] == "GH_TOKEN"
    assert len(secrets[1]["repos"]) == 2


async def test_get_org_secrets_empty():
    """Tests getting org secrets"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    api = Api(test_pat, "2022-11-28", client=mock_client)

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"total_count": 0, "secrets": []}

    secrets = await api.get_org_secrets("testOrg")

    assert secrets == []


async def test_get_repo_org_secrets():
    """Tests getting org secrets accessible to a repo."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "total_count": 3,
        "secrets": [{}, {}],
    }

    api = Api(test_pat, "2022-11-28", client=mock_client)

    secrets = await api.get_repo_org_secrets("testOrg/testRepo")

    assert len(secrets) == 2


@patch("gatox.github.api.asyncio.sleep")
async def test_handle_ratelimit(mock_time):
    """Test rate limit handling"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    api = Api(test_pat, "2022-11-28", client=mock_client)

    test_headers = {
        "X-Ratelimit-Remaining": 100,
        "Date": "Fri, 09 Jun 2023 22:12:41 GMT",
        "X-Ratelimit-Reset": 1686351401,
        "X-Ratelimit-Resource": "core",
        "X-RateLimit-Limit": 5000,
    }

    await api._Api__check_rate_limit(test_headers)

    mock_time.assert_called_once()


async def test_commit_workflow():
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response

    mock_get_responses = [
        {"default_branch": "main"},
        {"sha": "123"},
        {"tree": {"sha": "456"}},
        {"sha": "789", "tree": []},
    ]
    mock_post_responses = [
        {"sha": "abc"},
        {"sha": "def"},
        {"sha": "ghi"},
        {"sha": "jkl"},
    ]

    mock_response.status_code = 200
    mock_response.json.side_effect = mock_get_responses

    # For post calls, override the json and status_code as needed.
    def post_side_effect(*args, **kwargs):
        response = MagicMock()
        response.status_code = 201
        response.json.return_value = mock_post_responses.pop(0)
        return response

    mock_client.post.side_effect = post_side_effect

    api = Api(test_pat, "2022-11-28", client=mock_client)
    result = await api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    assert result == "ghi"
    # 4 get calls and 4 post calls expected


async def test_commit_workflow_failure():
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response

    mock_get_responses = [
        {"default_branch": "main"},
        {"sha": "123"},
        {"tree": {"sha": "456"}},
        {"sha": "789", "tree": []},
    ]
    mock_post_responses = [
        {"sha": "abc"},
        {"sha": "def"},
        {"sha": "ghi"},
        {"sha": "jkl"},
    ]

    mock_response.status_code = 200
    mock_response.json.side_effect = mock_get_responses

    def post_side_effect(*args, **kwargs):
        response = MagicMock()
        response.status_code = 400
        response.json.return_value = mock_post_responses.pop(0)
        return response

    mock_client.post.side_effect = post_side_effect

    api = Api(test_pat, "2022-11-28", client=mock_client)
    result = await api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    assert result is None


async def test_commit_workflow_failure2():
    # Arrange
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_client.post.return_value = mock_response

    mock_get_responses = [
        {"default_branch": "main"},
        {"sha": "123"},
        {"tree": {"sha": "456"}},
        {"sha": "789", "tree": []},
    ]
    mock_post_responses = [
        {"sha": "abc"},
        {"sha": "def"},
        {"sha": "ghi"},
        {"sha": "jkl"},
    ]

    mock_response.status_code = 200
    mock_response.json.side_effect = mock_get_responses

    def post_side_effect(*args, **kwargs):
        response = MagicMock()
        response.status_code = 404
        response.json.return_value = mock_post_responses.pop(0)
        return response

    mock_client.post.side_effect = post_side_effect

    api = Api(test_pat, "2022-11-28", client=mock_client)
    result = await api.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    assert result is None


async def test_graphql_org_query():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.post.return_value = mock_response

    mock_results = {
        "data": {
            "organization": {
                "repositories": {
                    "edges": [
                        {
                            "node": {"name": "TestWF2"},
                            "cursor": "Y3Vyc29yOnYyOpHOLK21Tw==",
                        },
                        {
                            "node": {"name": "TestPwnRequest"},
                            "cursor": "Y3Vyc29yOnYyOpHOLK24YQ==",
                        },
                        {
                            "node": {"name": "BH_DC_2024Demo"},
                            "cursor": "Y3Vyc29yOnYyOpHOMR_3jQ==",
                        },
                    ],
                    "pageInfo": {
                        "endCursor": "Y3Vyc29yOnYyOpHOMR_3jQ==",
                        "hasNextPage": False,
                    },
                }
            }
        }
    }

    mock_response.status_code = 200
    mock_response.json.return_value = mock_results

    api = Api(test_pat, "2022-11-28", client=mock_client)
    names = await api.get_org_repo_names_graphql("testOrg", "PUBLIC")

    assert "TestWF2" in names
    assert "TestPwnRequest" in names
    assert "BH_DC_2024Demo" in names


async def test_graphql_org_query_badtype():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    api = Api(test_pat, "2022-11-28", client=mock_client)

    with pytest.raises(ValueError):
        await api.get_org_repo_names_graphql("testOrg", "UNKNOWN")


async def test_graphql_mergedat_query():
    """Test GraphQL merge date query."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.post.return_value = mock_response

    mock_results = {
        "data": {
            "repository": {
                "commit": {
                    "associatedPullRequests": {
                        "edges": [
                            {
                                "node": {
                                    "merged": True,
                                    "mergedAt": "2024-06-21T09:57:58Z",
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    mock_response.status_code = 200
    mock_response.json.return_value = mock_results

    api = Api(test_pat, "2022-11-28", client=mock_client)
    date = await api.get_commit_merge_date(
        "testOrg/testRepo", "9659fdc7ba35a9eba00c183bccc67083239383e8"
    )

    assert date == "2024-06-21T09:57:58Z"


async def test_get_user_type():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.return_value = {"type": "User"}

    api = Api(test_pat, "2022-11-28", client=mock_client)

    user_type = await api.get_user_type("someUser")

    assert user_type == "User"


async def test_get_user_repos():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"full_name": "testRepo", "archived": False},
        {"full_name": "testRepo2", "archived": False},
    ]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    repos = await api.get_user_repos("someUser")

    assert repos[0] == "testRepo"
    assert repos[1] == "testRepo2"


async def test_get_own_repos_single_page():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    # Mock the API response for a single page
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"full_name": "owner/testRepo", "archived": False},
        {"full_name": "owner/testRepo2", "archived": False},
    ]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    repos = await api.get_own_repos()
    assert repos == ["owner/testRepo", "owner/testRepo2"]
    mock_client.get.assert_called_once()


async def test_get_own_repos_multiple_pages():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    MagicMock()

    def generate_repo_list():
        """
        Generate a list containing 100 copies of a predefined repository dictionary.
        """
        repo_dict = {"full_name": "owner/repo1", "archived": False}
        return [repo_dict for _ in range(100)]

    # Mock the API response for multiple pages
    mock_client.get.side_effect = [
        MagicMock(status_code=200, json=MagicMock(return_value=generate_repo_list())),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value=[{"full_name": "owner/repo101", "archived": False}]
            ),
        ),
    ]

    api = Api(test_pat, "2022-11-28", client=mock_client)
    repos = await api.get_own_repos()
    assert len(repos) == 101
    assert mock_client.get.call_count == 2


async def test_get_own_repos_empty_response():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    # Mock the API response for an empty response
    mock_response.status_code = 200
    mock_response.json.return_value = []

    api = Api(test_pat, "2022-11-28", client=mock_client)
    repos = await api.get_own_repos()
    assert repos == []
    mock_client.get.assert_called_once()


async def test_retrieve_raw_action_public_repo():
    """Test retrieving a GitHub action from a public repository using raw.githubusercontent.com."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    # Mock response for the raw file request
    mock_raw_response = MagicMock()
    mock_raw_response.status_code = 200
    mock_raw_response.text = "name: 'Test Action'\ndescription: 'This is a test action'"

    # Set up the client mock to return our raw response
    mock_client.get.return_value = mock_raw_response

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    # Test the method with a .yml file path
    result = await abstraction_layer.retrieve_raw_action(
        "testorg/testrepo", "actions/test-action/action.yml", "main"
    )

    # Verify the correct URL was called
    mock_client.get.assert_called_with(
        "https://raw.githubusercontent.com/testorg/testrepo/main/actions/test-action/action.yml",
        headers={"Authorization": "None", "Accept": "text/plain"},
    )

    assert result == "name: 'Test Action'\ndescription: 'This is a test action'"


async def test_retrieve_raw_action_private_repo():
    """Test retrieving a GitHub action from a private repository using the GitHub API."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    # Mock response for raw file request (this should fail for private repos)
    mock_raw_response = MagicMock()
    mock_raw_response.status_code = 404

    # Mock response for the API request - only action.yml succeeds
    mock_api_response_success = MagicMock()
    mock_api_response_success.status_code = 200
    mock_api_response_success.json.return_value = {
        "content": base64.b64encode(
            b"name: 'Test Action'\ndescription: 'This is a test action'"
        ).decode()
    }

    mock_api_response_404 = MagicMock()
    mock_api_response_404.status_code = 404

    # Set up the client mock to return our responses
    def mock_get_side_effect(*args, **kwargs):
        url = args[0]
        if "raw.githubusercontent.com" in url:
            # All raw requests fail (private repo)
            return mock_raw_response
        elif "/contents/" in url:
            # API requests - action.yml succeeds, action.yaml fails
            if "action.yml" in url:
                return mock_api_response_success
            else:
                return mock_api_response_404
        return mock_raw_response

    mock_client.get.side_effect = mock_get_side_effect

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    # Test the method with a directory path (should try action.yml and action.yaml)
    result = await abstraction_layer.retrieve_raw_action(
        "testorg/testrepo", "actions/test-action", "main"
    )

    # Verify that calls were made in the expected order
    calls = mock_client.get.call_args_list

    # Should try both raw URLs first (action.yml, then action.yaml)
    assert len(calls) >= 3  # At least 2 raw calls + 1 API call

    # First raw URL attempt
    assert (
        "https://raw.githubusercontent.com/testorg/testrepo/main/actions/test-action/action.yml"
        in calls[0][0][0]
    )

    # Second raw URL attempt
    assert (
        "https://raw.githubusercontent.com/testorg/testrepo/main/actions/test-action/action.yaml"
        in calls[1][0][0]
    )

    # API call that succeeds
    assert (
        "/repos/testorg/testrepo/contents/actions/test-action/action.yml"
        in calls[2][0][0]
    )

    assert result == "name: 'Test Action'\ndescription: 'This is a test action'"


async def test_retrieve_raw_action_not_found():
    """Test retrieving a GitHub action that doesn't exist."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    # Mock responses for both raw file and API requests
    mock_response = MagicMock()
    mock_response.status_code = 404

    # Set up the client mock to return 404 for all requests
    mock_client.get.return_value = mock_response

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    # Test with a non-existent action
    result = await abstraction_layer.retrieve_raw_action(
        "testorg/testrepo", "actions/nonexistent-action", "main"
    )

    # Should try both action.yml and action.yaml paths
    assert mock_client.get.call_count >= 4  # 2 raw URLs + 2 API calls

    # Should return None when action is not found
    assert result is None


async def test_retrieve_raw_action_path_normalization():
    """Test path normalization in retrieve_raw_action."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    # Mock successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "name: 'Test Action'\ndescription: 'This is a test action'"

    mock_client.get.return_value = mock_response

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    # Test with double slashes in path
    result = await abstraction_layer.retrieve_raw_action(
        "testorg/testrepo", "actions//test-action//action.yml", "main"
    )

    # Verify the URL was normalized (double slashes replaced)
    mock_client.get.assert_called_with(
        "https://raw.githubusercontent.com/testorg/testrepo/main/actions/test-action/action.yml",
        headers={"Authorization": "None", "Accept": "text/plain"},
    )

    assert result == "name: 'Test Action'\ndescription: 'This is a test action'"
