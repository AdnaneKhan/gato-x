"""Tests for :class:`gatox.github.user_api.UserApi`.

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
    user_info = await abstraction_layer.user.check_user()

    assert user_info["user"] == "TestUserName"
    assert "repo" in user_info["scopes"]


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
    result = await abstraction_layer.user.check_organizations()

    assert len(result) == 5
    assert result[0] == "org1"
    assert result[1] == "org2"
    assert result[2] == "org3"
    assert result[3] == "org4"
    assert result[4] == "org5"


async def test_get_user_type():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response

    mock_response.status_code = 200
    mock_response.json.return_value = {"type": "User"}

    api = Api(test_pat, "2022-11-28", client=mock_client)

    user_type = await api.user.get_user_type("someUser")

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
    repos = await api.user.get_user_repos("someUser")

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
    repos = await api.user.get_own_repos()
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
    repos = await api.user.get_own_repos()
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
    repos = await api.user.get_own_repos()
    assert repos == []
    mock_client.get.assert_called_once()
