import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gatox.cli.output import Output
from gatox.github.api import Api

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


async def test_invalid_pat():
    """Test calling a request with an invalid PAT"""
    test_pat = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    mock_client = AsyncMock()

    mock_response = MagicMock()
    mock_client.get.return_value = mock_response
    mock_response.status_code = 401

    abstraction_layer = Api(test_pat, "2022-11-28", client=mock_client)
    assert await abstraction_layer.user.check_user() is None


@patch("gatox.github.api_base.asyncio.sleep")
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

    await api._check_rate_limit(test_headers)

    mock_time.assert_called_once()
