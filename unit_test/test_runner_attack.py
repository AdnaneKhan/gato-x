from unittest.mock import AsyncMock, MagicMock, patch

from gatox.attack.runner.webshell import WebShell
from gatox.github.api import Api


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_shell_workflow_attack(mock_api):
    """
    Test the webshell attack on a workflow.
    """

    mock_json1 = MagicMock(status_code=200)
    mock_json2 = MagicMock(status_code=201)

    mock_json1.json.return_value = [
        {
            "tag_name": "v2.317.0",
        }
    ]
    mock_json2.json.return_value = {
        "token": "LLBF3JGZDX3P5PMEXLND6TS6FCWO6",
        "expires_at": "2020-01-22T12:13:35.123-08:00",
    }

    mock_api.return_value.call_get.return_value = mock_json1
    mock_api.return_value.call_post.return_value = mock_json2

    websheller = WebShell(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    formatted_gist = await websheller.format_ror_gist("c2user/c2repo", "linux", "x64")

    assert formatted_gist is not None
    assert "actions-runner-linux-x64-2.317.0.tar.gz" in formatted_gist
