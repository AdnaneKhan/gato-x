from unittest.mock import AsyncMock, MagicMock, call, patch

import httpx

from gatox.cli.output import Output
from gatox.github.api_base import ApiBase
from gatox.github.search import Search
from gatox.search.search import Searcher
from unit_test.api_mock import make_api_mock

Output(True)

_HTTPX_ASYNC_CLIENT_SEND = httpx.AsyncClient.send


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
async def test_search_api_encodes_custom_query_as_params(mock_time):
    mock_client = AsyncMock()
    custom_query = (
        "org:somecompany lang:yaml path:.github/workflows "
        "/(issue_comment|pull_request_target|issues:)/"
    )

    mock_client.call_get.return_value = MagicMock(
        status_code=200,
        json=MagicMock(return_value={"items": [], "total_count": 0}),
        links={},
    )

    searcher = Search(mock_client)

    await searcher.search_enumeration(custom_query=custom_query)

    mock_client.call_get.assert_awaited_once_with(
        "/search/code",
        params={
            "q": custom_query,
            "sort": "indexed",
            "per_page": "100",
            "page": 1,
        },
    )


async def test_search_api_preserves_reserved_query_characters(monkeypatch):
    requests = []
    custom_query = (
        "org:somecompany lang:yaml path:.github/workflows "
        r"/pull_request_target.+write/"
    )

    def handle_request(request):
        requests.append(request)
        return httpx.Response(
            status_code=200,
            json={"items": [], "total_count": 0},
        )

    # The autouse fixture blocks AsyncClient.send; restore it for MockTransport.
    monkeypatch.setattr(httpx.AsyncClient, "send", _HTTPX_ASYNC_CLIENT_SEND)
    transport = httpx.MockTransport(handle_request)
    async with httpx.AsyncClient(transport=transport) as client:
        searcher = Search(ApiBase("test-token", client=client))
        await searcher.search_enumeration(custom_query=custom_query)

    assert len(requests) == 1
    assert requests[0].url.path == "/search/code"
    assert requests[0].url.params["q"] == custom_query
    assert b"%2B" in requests[0].url.query


@patch("gatox.github.search.asyncio.sleep")
async def test_search_api_uses_next_link_without_initial_params(mock_time):
    mock_client = AsyncMock()
    custom_query = "org:somecompany path:.github/workflows"
    next_page = "https://api.github.com/search/code?q=custom&page=2"
    mock_client.call_get.side_effect = [
        MagicMock(
            status_code=200,
            json=MagicMock(return_value={"items": [], "total_count": 0}),
            links={"next": {"url": next_page}},
        ),
        MagicMock(
            status_code=200,
            json=MagicMock(return_value={"items": [], "total_count": 0}),
            links={},
        ),
    ]

    searcher = Search(mock_client)
    await searcher.search_enumeration(custom_query=custom_query)

    assert mock_client.call_get.await_args_list == [
        call(
            "/search/code",
            params={
                "q": custom_query,
                "sort": "indexed",
                "per_page": "100",
                "page": 1,
            },
        ),
        call("/search/code?q=custom&page=2", params=None),
    ]
    mock_time.assert_awaited_once_with(5)


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
@patch("gatox.search.search.Api", return_value=make_api_mock())
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
@patch("gatox.search.search.Api", return_value=make_api_mock())
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
@patch("gatox.search.search.Api", return_value=make_api_mock())
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

    assert res == set()
