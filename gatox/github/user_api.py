"""Sub-API: current-user / user-by-name endpoints."""

from __future__ import annotations

import logging

from gatox.github.api_base import ApiBase, SubApi

logger = logging.getLogger(__name__)


class UserApi(SubApi):
    """Endpoints rooted at ``/user`` and ``/users/{username}``."""

    def __init__(self, base: ApiBase) -> None:
        super().__init__(base)

    async def check_user(self) -> dict | None:
        """Return ``{user, scopes, name, expiration}`` for the authenticated PAT.

        The function is cheap and effectively also tests connectivity /
        token validity. Returns ``None`` if the token is rejected.
        """
        result = await self._base.call_get("/user")
        if result.status_code == 200:
            resp_headers = result.headers.get("x-oauth-scopes")
            if resp_headers:
                scopes = [scope.strip() for scope in resp_headers.split(",")]
            else:
                scopes = []

            exp_header = result.headers.get("github-authentication-token-expiration")
            expiration = exp_header if exp_header else None

            user_scopes = {
                "user": result.json()["login"],
                "scopes": scopes,
                "name": result.json()["name"],
                "expiration": expiration,
            }

            return user_scopes
        else:
            logger.warning("Provided token was not valid or has expired!")

        return None

    async def check_organizations(self) -> list[str]:
        """Return the list of org logins the authenticated user belongs to."""
        organizations: list[str] = []
        page = 1
        per_page = 100

        while True:
            params = {"page": page, "per_page": per_page}
            result = await self._base.call_get("/user/orgs", params=params)

            if result.status_code == 200:
                orgs = result.json()
                if not orgs:
                    break

                organizations.extend([org["login"] for org in orgs])
                page += 1
            elif result.status_code == 403:
                break
            else:
                break

        return organizations

    async def get_user_type(self, username: str) -> str | None:
        """Return ``type`` (User / Organization / ...) for ``username`` or ``None``."""
        result = await self._base.call_get(f"/users/{username}")

        if result.status_code == 200:
            return result.json()["type"]
        return None

    async def get_own_repos(
        self, affiliation: str = "owner,collaborator", visibility: str = "all"
    ) -> list[str]:
        """Return all non-archived repos the user owns / collaborates on."""
        repos: list[str] = []

        get_params: dict = {
            "affiliation": affiliation,
            "visibility": visibility,
            "per_page": 100,
            "page": 1,
        }

        result = await self._base.call_get("/user/repos", params=get_params)
        if result.status_code == 200:
            listing = result.json()
            repos.extend(
                [repo["full_name"] for repo in listing if not repo["archived"]]
            )

            while len(listing) == 100:
                get_params["page"] += 1
                result = await self._base.call_get("/user/repos", params=get_params)
                if result.status_code == 200:
                    listing = result.json()
                    repos.extend(
                        [repo["full_name"] for repo in listing if not repo["archived"]]
                    )
        return repos

    async def get_user_repos(self, username: str) -> list[str]:
        """Return all non-archived public repos owned by ``username``."""
        repos: list[str] = []

        get_params: dict = {"type": "owner", "per_page": 100, "page": 1}

        result = await self._base.call_get(
            f"/users/{username}/repos", params=get_params
        )
        if result.status_code == 200:
            listing = result.json()
            repos.extend(
                [repo["full_name"] for repo in listing if not repo["archived"]]
            )

            while len(listing) == 100:
                get_params["page"] += 1
                result = await self._base.call_get(
                    f"/users/{username}/repos", params=get_params
                )
                if result.status_code == 200:
                    listing = result.json()
                    repos.extend(
                        [repo["full_name"] for repo in listing if not repo["archived"]]
                    )
        return repos

    async def create_repository(self, repository_name: str) -> str | bool:
        """Create a private repository for the authenticated user.

        Returns:
            The full repository name on success, ``False`` otherwise.
        """
        params = {"private": True, "name": repository_name}

        response = await self._base.call_post("/user/repos", params=params)

        if response.status_code == 201:
            return response.json()["full_name"]
        else:
            return False
