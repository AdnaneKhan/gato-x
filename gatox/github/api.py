"""Public ``Api`` orchestrator for the GitHub REST/GraphQL API.

This module used to be a monolithic ~1900-line class. It has been split
into a small orchestrator (this file) plus a handful of grouped
sub-APIs:

* :class:`gatox.github.user_api.UserApi`
* :class:`gatox.github.org_api.OrgApi`
* :class:`gatox.github.repo_api.RepoApi`
* :class:`gatox.github.commit_api.CommitApi`
* :class:`gatox.github.action_api.ActionApi`
* :class:`gatox.github.app_api.AppApi`

All shared HTTP plumbing lives on :class:`gatox.github.api_base.ApiBase`,
from which :class:`Api` inherits, so existing call sites that touched
``self.api.call_get(...)``, ``self.api.is_app_token()``,
``self.api.close()`` or ``async with Api(...) as api`` continue to work
unchanged.

Migration of higher-level call sites: ``self.api.foo(...)`` becomes
``self.api.<group>.foo(...)`` (see ``REFACTOR-PLAN.md``).
"""

from __future__ import annotations

import logging

import httpx

from gatox.github.action_api import ActionApi
from gatox.github.api_base import ApiBase
from gatox.github.app_api import AppApi
from gatox.github.commit_api import CommitApi
from gatox.github.org_api import OrgApi
from gatox.github.repo_api import RepoApi
from gatox.github.user_api import UserApi

logger = logging.getLogger(__name__)


class Api(ApiBase):
    """Top-level orchestrator. Owns a single :class:`ApiBase` and the sub-APIs.

    The constructor wires up every sub-API against the shared HTTP
    infrastructure (token, headers, httpx client, rate-limit guard) that
    lives on :class:`ApiBase`. The orchestrator itself only carries the
    lifecycle helpers (``__aenter__`` / ``__aexit__`` / ``close``) and
    ``is_app_token``, which it inherits from ``ApiBase``.
    """

    # Class-level placeholders so ``AsyncMock(spec=Api)`` (used widely in
    # the tests) recognises the sub-API attribute names — ``dir()`` only
    # surfaces real class attributes, not pure annotations. Real
    # ``__init__`` overwrites each of these with a constructed sub-API.
    repo: RepoApi = None  # type: ignore[assignment]
    org: OrgApi = None  # type: ignore[assignment]
    user: UserApi = None  # type: ignore[assignment]
    commit: CommitApi = None  # type: ignore[assignment]
    action: ActionApi = None  # type: ignore[assignment]
    app: AppApi = None  # type: ignore[assignment]

    def __init__(
        self,
        pat: str,
        version: str = "2022-11-28",
        http_proxy: str | None = None,
        socks_proxy: str | None = None,
        github_url: str | None = "https://api.github.com",
        client: httpx.AsyncClient | None = None,
        app_permissions: list | None = None,
    ) -> None:
        """Initialise the shared infra and construct each sub-API.

        See :class:`gatox.github.api_base.ApiBase` for the meaning of
        every parameter — they are all forwarded verbatim.
        """
        super().__init__(
            pat=pat,
            version=version,
            http_proxy=http_proxy,
            socks_proxy=socks_proxy,
            github_url=github_url,
            client=client,
            app_permissions=app_permissions,
        )

        # Construct each grouped sub-API once, passing the *same*
        # ``ApiBase`` (this object) so every sub-API shares the single
        # httpx client / token / rate-limit state.
        self.repo = RepoApi(self)
        self.org = OrgApi(self)
        self.user = UserApi(self)
        self.commit = CommitApi(self)
        self.action = ActionApi(self)
        self.app = AppApi(self)
