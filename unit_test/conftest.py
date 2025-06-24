import pytest
import httpx


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """
    Fixture to block real network calls during tests,
    raising an error if any attempt to send a request is made.
    """

    def mock_request(*args, **kwargs):
        raise RuntimeError("Blocked a real network call during tests.")

    monkeypatch.setattr(httpx.Client, "send", mock_request)
    monkeypatch.setattr(httpx.AsyncClient, "send", mock_request)


@pytest.fixture(autouse=True)
async def no_async_sleep(monkeypatch):
    """
    Fixture to make asyncio.sleep a no-op during tests.
    """

    async def mock_sleep(delay, result=None):
        return result  # Immediately return, effectively doing nothing

    monkeypatch.setattr("asyncio.sleep", mock_sleep)
