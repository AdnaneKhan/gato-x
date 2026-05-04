"""Sub-API: GitHub App installation endpoints used by ``--machine`` mode."""

from __future__ import annotations

import logging

from gatox.github.api_base import ApiBase, SubApi

logger = logging.getLogger(__name__)


class AppApi(SubApi):
    """Endpoints rooted at ``/app`` and ``/installation`` / ``/app/installations/...``."""

    def __init__(self, base: ApiBase) -> None:
        super().__init__(base)

    async def get_installation_repos(self) -> dict | None:
        """List repositories accessible to the current installation token."""
        response = await self._base.call_get("/installation/repositories")
        if response.status_code == 200:
            return response.json()
        return None

    async def get_app_installations(self) -> list | None:
        """Return all installations for the GitHub App."""
        response = await self._base.call_get("/app/installations")
        if response.status_code == 200:
            return response.json()
        return None

    async def get_installation_access_token(self, installation_id: str) -> dict | None:
        """Mint an installation access token for ``installation_id``."""
        response = await self._base.call_post(
            f"/app/installations/{installation_id}/access_tokens"
        )
        if response.status_code == 201:
            return response.json()
        return None

    async def get_installation_info(self, installation_id: str) -> dict | None:
        """Return metadata about a specific installation."""
        response = await self._base.call_get(f"/app/installations/{installation_id}")
        if response.status_code == 200:
            return response.json()
        return None

    async def get_installation_repositories(self, installation_id: str) -> dict | None:
        """Return repositories visible to a specific installation."""
        response = await self._base.call_get(
            f"/app/installations/{installation_id}/repositories"
        )
        if response.status_code == 200:
            return response.json()
        return None

    async def get_app_info(self) -> dict | None:
        """Return ``GET /app`` — GitHub App identity / permissions block."""
        response = await self._base.call_get("/app")
        if response.status_code == 200:
            return response.json()
        return None
