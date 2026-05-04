"""Tests for :class:`gatox.github.org_api.OrgApi`.

Carved out of ``unit_test/test_api.py`` after the api split (#144).
The pre-split monolithic file lives on at the same path and now only
keeps the lifecycle/init tests; per-sub-API tests moved here.
"""

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from gatox.cli.output import Output
from gatox.github.api import Api

logging.root.setLevel(logging.DEBUG)

output = Output(False)


async def test_validate_sso():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    mock_response = MagicMock()

    mock_response.status_code = 200

    mock_client.get.return_value = mock_response
    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    res = await abstraction_layer.org.validate_sso("testorg", "testRepo")

    assert res is True


async def test_validate_sso_fail():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()

    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    res = await abstraction_layer.org.validate_sso("testorg", "testRepo")

    assert res is False


async def test_get_org():
    """Test retrievign org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 200
    mock_response.json.return_value = {"org1": "fakeorgdata"}

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.org.get_organization_details("testOrg")

    assert result["org1"] == "fakeorgdata"


async def test_get_org_notfound():
    """Test 404 code when retrieving org info."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 404

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.org.get_organization_details("testOrg")

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
    result = await abstraction_layer.org.check_org_runners("testOrg")

    assert result == {"total_count": 5}


async def test_check_org_runners_fail():
    """Test method to retrieve runners from org."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 403

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    result = await abstraction_layer.org.check_org_runners("testOrg")

    assert result is None


async def test_check_org_repos_invalid():
    """Test method to retrieve repos from org with an invalid type."""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)

    with pytest.raises(ValueError):
        await abstraction_layer.org.check_org_repos("testOrg", "invalid")


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
    result = await abstraction_layer.org.check_org_repos("testOrg", "internal")

    assert len(result) == 5


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
    secrets = await api.org.get_org_secrets("testOrg")

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

    secrets = await api.org.get_org_secrets("testOrg")

    assert secrets == []


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
    names = await api.org.get_org_repo_names_graphql("testOrg", "PUBLIC")

    assert "TestWF2" in names
    assert "TestPwnRequest" in names
    assert "BH_DC_2024Demo" in names


async def test_graphql_org_query_badtype():
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()
    api = Api(test_pat, "2022-11-28", client=mock_client)

    with pytest.raises(ValueError):
        await api.org.get_org_repo_names_graphql("testOrg", "UNKNOWN")
