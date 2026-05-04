"""Tests for :class:`gatox.github.repo_api.RepoApi`.

Carved out of ``unit_test/test_api.py`` after the api split (#144).
The pre-split monolithic file lives on at the same path and now only
keeps the lifecycle/init tests; per-sub-API tests moved here.
"""

import base64
import logging
from unittest.mock import AsyncMock, MagicMock

from gatox.cli.output import Output
from gatox.github.api import Api

logging.root.setLevel(logging.DEBUG)

output = Output(False)


async def test_delete_repo():
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 204

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.repo.delete_repository("testOrg/TestRepo")

    assert result is True


async def test_delete_fail():
    """Test forking a repository"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.repo.delete_repository("testOrg/TestRepo")

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
    result = await abstraction_layer.repo.fork_repository("testOrg/TestRepo")

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
    result = await abstraction_layer.repo.fork_repository("testOrg/TestRepo")
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
    result = await abstraction_layer.repo.fork_repository("testOrg/TestRepo")
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
    result = await abstraction_layer.repo.fork_repository("testOrg/TestRepo")
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
    result = await abstraction_layer.repo.create_fork_pr(
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
    result = await abstraction_layer.repo.create_fork_pr(
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
    result = await abstraction_layer.repo.get_repository("testOrg/TestRepo")

    assert result["repo1"] == "fakerepodata"


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
    ymls = await api.repo.retrieve_workflow_ymls("testOrg/testRepo")

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
    ymls = await api.repo.retrieve_workflow_ymls_ref("testOrg/testRepo", sha)

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
    secrets = await api.repo.get_secrets("testOrg/testRepo")

    assert len(secrets) == 3


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

    secrets = await api.repo.get_repo_org_secrets("testOrg/testRepo")

    assert len(secrets) == 2


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
    result = await abstraction_layer.repo.retrieve_raw_action(
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
    result = await abstraction_layer.repo.retrieve_raw_action(
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
    result = await abstraction_layer.repo.retrieve_raw_action(
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
    result = await abstraction_layer.repo.retrieve_raw_action(
        "testorg/testrepo", "actions//test-action//action.yml", "main"
    )

    # Verify the URL was normalized (double slashes replaced)
    mock_client.get.assert_called_with(
        "https://raw.githubusercontent.com/testorg/testrepo/main/actions/test-action/action.yml",
        headers={"Authorization": "None", "Accept": "text/plain"},
    )

    assert result == "name: 'Test Action'\ndescription: 'This is a test action'"
