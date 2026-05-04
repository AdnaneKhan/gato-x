"""Test helpers for mocking the new grouped :class:`~gatox.github.api.Api`.

After the api split (#144) every method moved onto a sub-API
(``api.repo.foo``, ``api.action.foo``, ...). ``AsyncMock(spec=Api)`` no
longer auto-spec'd the sub-API attributes recursively, so each test that
mocked ``Api`` would receive a plain ``MagicMock`` for ``api.repo`` and
its child methods would not be awaitable.

:func:`make_api_mock` returns an ``AsyncMock(spec=Api)`` with each
sub-API pre-replaced by its own ``AsyncMock(spec=<group>Api)``. This
mirrors the old, monolithic-spec behaviour and keeps existing test
shapes intact: callers can still set ``api.<method>.return_value`` for
parent-level methods (``call_get`` etc.) and ``api.<group>.<method>.return_value``
for grouped methods.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from gatox.github.action_api import ActionApi
from gatox.github.api import Api
from gatox.github.app_api import AppApi
from gatox.github.commit_api import CommitApi
from gatox.github.org_api import OrgApi
from gatox.github.repo_api import RepoApi
from gatox.github.user_api import UserApi


def make_api_mock() -> AsyncMock:
    """Return an ``AsyncMock(spec=Api)`` with each sub-API pre-spec'd.

    Use this anywhere a test previously did ``AsyncMock(Api)`` /
    ``AsyncMock(spec=Api)``.
    """
    mock = AsyncMock(spec=Api)
    mock.repo = AsyncMock(spec=RepoApi)
    mock.org = AsyncMock(spec=OrgApi)
    mock.user = AsyncMock(spec=UserApi)
    mock.commit = AsyncMock(spec=CommitApi)
    mock.action = AsyncMock(spec=ActionApi)
    mock.app = AsyncMock(spec=AppApi)
    return mock
