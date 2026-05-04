"""Tests for :class:`gatox.github.commit_api.CommitApi`.

Carved out of ``unit_test/test_api.py`` after the api split (#144).
The pre-split monolithic file lives on at the same path and now only
keeps the lifecycle/init tests; per-sub-API tests moved here.
"""

import logging
from unittest.mock import AsyncMock, MagicMock

from gatox.cli.output import Output
from gatox.github.api import Api

logging.root.setLevel(logging.DEBUG)

output = Output(False)


async def test_get_repo_branch():
    """Test retrieving the existence of a branch."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.commit.get_repo_branch("repo", "branch") == 1

    mock_response.status_code = 404
    assert await api.commit.get_repo_branch("repo", "branch") == 0

    mock_response.status_code = 401
    assert await api.commit.get_repo_branch("repo", "branch") == -1


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
    assert await api.commit.create_branch("test_repo", "abcdefg") is True


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
    assert await api.commit.create_branch("test_repo", "abcasync defg") is False


async def test_delete_branch():
    """Test deleting branch"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.delete.return_value = mock_response
    mock_response.status_code = 204

    api = Api(test_pat, "2022-11-28", client=mock_client)
    assert await api.commit.delete_branch("testRepo", "testBranch")


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

    commit_sha = await api.commit.commit_file(
        "testOrg/testRepo",
        "testBranch",
        "test/newFile",
        test_filedata,
        commit_author="testUser",
        commit_email="testemail@example.org",
    )

    assert commit_sha == test_sha


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
    result = await api.commit.commit_workflow(
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
    result = await api.commit.commit_workflow(
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
    result = await api.commit.commit_workflow(
        "test_repo", "test_branch", b"test_content", "test_file"
    )

    assert result is None


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
    date = await api.commit.get_commit_merge_date(
        "testOrg/testRepo", "9659fdc7ba35a9eba00c183bccc67083239383e8"
    )

    assert date == "2024-06-21T09:57:58Z"
