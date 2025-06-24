from unittest.mock import patch, MagicMock, AsyncMock
from gatox.github.search import Search
from gatox.search.search import Searcher
from gatox.cli.output import Output
from gatox.github.api import Api

Output(True)


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api(mock_time):
    mock_client = AsyncMock()

    mock_client.call_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "items": [
                        {
                            "path": ".github/workflows/yaml_wf.yml",
                            "repository": {
                                "fork": False,
                                "full_name": "testOrg/testRepo",
                            },
                        }
                    ],
                    "total_count": 1,
                }
            ),
            links={},
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(return_value={"items": [], "total_count": 0}),
            links={},
        ),
    ]

    searcher = Search(mock_client)

    res = await searcher.search_enumeration("testOrganization")
    assert len(res) == 1
    assert "testOrg/testRepo" in res


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api_cap(mock_time, capfd):
    mock_client = AsyncMock()

    mock_client.call_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "items": [
                        {
                            "path": ".github/workflows/yaml_wf.yml",
                            "repository": {
                                "fork": False,
                                "full_name": "testOrg/testRepo",
                            },
                        }
                    ],
                    "total_count": 1,
                }
            ),
            links={"next": {"url": "test"}},
        ),
        MagicMock(status_code=422),
    ]

    searcher = Search(mock_client)

    res = await searcher.search_enumeration("testOrganization")
    assert len(res) == 1
    out, err = capfd.readouterr()
    assert "Search failed with response code 422" in out


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api_ratelimit(mock_time, capfd):
    mock_client = AsyncMock()

    mock_client.call_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "items": [
                        {
                            "path": ".github/workflows/yaml_wf.yml",
                            "repository": {
                                "fork": False,
                                "full_name": "testOrg/testRepo",
                            },
                        }
                    ],
                    "total_count": 1,
                }
            ),
            links={"next": {"url": "test"}},
        ),
        MagicMock(status_code=403, text="rate limit exceeded"),
        MagicMock(
            status_code=200,
            json=MagicMock(return_value={"items": [], "total_count": 0}),
            links={},
        ),
    ]

    searcher = Search(mock_client)

    res = await searcher.search_enumeration("testOrganization")
    mock_time.assert_awaited()
    assert len(res) == 1

    out, err = capfd.readouterr()
    assert "[!] Secondary API Rate Limit Hit." in out


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api_permission(mock_time, capfd):
    mock_client = AsyncMock()

    mock_client.call_get.return_value = MagicMock(
        status_code=422,
        json=MagicMock(
            return_value={
                "message": "Validation Failed",
                "errors": [
                    {
                        "message": "The listed users and repositories cannot be "
                        "searched either because the resources do not exist or you "
                        "do not have permission to view them.",
                        "resource": "Search",
                        "field": "q",
                        "code": "invalid",
                    }
                ],
                "documentation_url": "https://docs.github.com/v3/search/",
            }
        ),
    )

    searcher = Search(mock_client)

    res = await searcher.search_enumeration("privateOrg")
    assert len(res) == 0
    out, err = capfd.readouterr()
    assert "Search failed with response code 422!" in out


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api_iniitalrl(mock_time, capfd):
    mock_client = AsyncMock()

    mock_client.call_get.side_effect = [
        MagicMock(
            status_code=403,
            json=MagicMock(
                return_value={
                    "documentation_url": "https://docs.github.com/en/free-pro-team@latest"
                    "/rest/overview/resources-in-the-rest-api#secondary-rate-limits",
                    "message": "You have exceeded a secondary rate limit"
                    ". Please wait a few minutes before you try again.",
                }
            ),
            text="rate limit",
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "items": [
                        {
                            "path": ".github/workflows/yaml_wf.yml",
                            "repository": {
                                "fork": False,
                                "full_name": "testOrg/testRepo",
                            },
                        }
                    ],
                    "total_count": 1,
                }
            ),
            links={},
        ),
    ]

    searcher = Search(mock_client)

    res = await searcher.search_enumeration("testOrg")
    assert len(res) == 1
    out, err = capfd.readouterr()
    assert "[!] Secondary API Rate Limit Hit." in out


@patch("gatox.github.search.asyncio.sleep")
@patch("gatox.search.search.Api", return_value=AsyncMock(Api))
async def test_search(mock_client, mock_time):
    mock_client.return_value.transport = None

    mock_client.return_value.call_get.return_value = MagicMock(
        status_code=200,
        json=MagicMock(
            return_value={
                "items": [
                    {"repository": {"full_name": "candidate1"}},
                    {"repository": {"full_name": "candidate2"}},
                ],
                "total_count": 2,
            }
        ),
        links={},
    )

    gh_search_runner = Searcher("ghp_AAAA")
    res = await gh_search_runner.use_search_api("targetOrg")
    assert res is not False


@patch("gatox.github.search.asyncio.sleep")
@patch("gatox.search.search.Api", return_value=AsyncMock(Api))
async def test_search_query(mock_client, mock_time, capfd):
    mock_client.return_value.transport = None
    mock_client.return_value.call_get.return_value = MagicMock(
        status_code=200,
        json=MagicMock(
            return_value={
                "items": [
                    {"repository": {"full_name": "candidate1"}},
                    {"repository": {"full_name": "candidate2"}},
                ]
            }
        ),
        links={},
    )

    gh_search_runner = Searcher("ghp_AAAA")

    await gh_search_runner.use_search_api(None, query="pull_request_target self-hosted")
    out, err = capfd.readouterr()
    assert "GitHub with the following query: pull_request_target self-hosted" in out


@patch("gatox.github.search.asyncio.sleep")
@patch("gatox.search.search.Api", return_value=AsyncMock(Api))
async def test_search_bad_token(mock_client, mock_time):
    mock_client.return_value.transport = None
    mock_client.return_value.call_get.return_value = MagicMock(
        status_code=401,
        json=MagicMock(
            return_value={
                "message": "Validation Failed",
                "errors": [
                    {
                        "message": "The listed users and repositories cannot be "
                        "searched either because the resources do not exist or you "
                        "do not have permission to view them.",
                        "resource": "Search",
                        "field": "q",
                        "code": "invalid",
                    }
                ],
                "documentation_url": "https://docs.github.com/v3/search/",
            }
        ),
    )

    gh_search_runner = Searcher("ghp_AAAA")
    res = await gh_search_runner.use_search_api("targetOrg")

    assert res == []
