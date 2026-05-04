"""Shared HTTP infrastructure for the GitHub :class:`Api` and its sub-APIs.

The original ``Api`` class was a 1900+ line monolith. To make things
testable and easier to navigate it has been split into one orchestrator
class plus a handful of grouped sub-APIs (see ``repo_api``, ``org_api``,
``commit_api``, ``user_api``, ``action_api``, ``app_api``).

Everything in this module is the *shared* state and behaviour that every
sub-API needs:

* the configured :class:`httpx.AsyncClient`,
* the request headers / proxy / SSL setup,
* the rate-limit guard,
* the small set of binary-log / raw-file helpers,
* the typed ``call_get`` / ``call_post`` / ... HTTP wrappers, and
* the ``__aenter__`` / ``__aexit__`` / ``close`` lifecycle.

``Api`` itself extends :class:`ApiBase`. Sub-APIs hold a reference to the
shared ``ApiBase`` instance via their constructor and reach the wire by
calling ``self._base.call_get(...)`` etc. There is exactly one HTTP
client per ``Api`` orchestrator, regardless of how many sub-APIs are
constructed.
"""

from __future__ import annotations

import asyncio
import copy
import io
import logging
import re
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx

from gatox.cli.output import Output

if TYPE_CHECKING:
    from gatox.github.action_api import ActionApi
    from gatox.github.app_api import AppApi
    from gatox.github.commit_api import CommitApi
    from gatox.github.org_api import OrgApi
    from gatox.github.repo_api import RepoApi
    from gatox.github.user_api import UserApi

logger = logging.getLogger(__name__)


class ApiBase:
    """Shared HTTP / rate-limit infrastructure used by every sub-API.

    This is a deliberate separation: ``ApiBase`` knows nothing about
    repos, orgs, commits, runs, etc. It only owns the plumbing every
    sub-API leans on. Sub-API classes take an :class:`ApiBase` instance
    via their constructor and use it to make wire calls.
    """

    RUNNER_RE = re.compile(r"Runner name: \'([\w+-.]+)\'")
    MACHINE_RE = re.compile(r"Machine name: \'([\w+-.]+)\'")
    RUNNERGROUP_RE = re.compile(r"Runner group name: \'([\w+-.]+)\'")
    RUNNERTYPE_RE = re.compile(r"([\w+-.]+)")

    RUN_THRESHOLD = 90

    # Forward declarations for the sub-API attributes that ``Api.__init__``
    # populates. Declaring them here lets sub-API code refer to sibling
    # sub-APIs (``self._base.repo.get_repository(...)``) and keeps pyright
    # happy without introducing a runtime import cycle.
    repo: RepoApi
    org: OrgApi
    user: UserApi
    commit: CommitApi
    action: ActionApi
    app: AppApi

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
        """Initialise the shared HTTP infrastructure.

        Args:
            pat: GitHub personal access token used for API calls.
            version: API version sent in ``X-GitHub-Api-Version``.
            http_proxy: Optional ``host:port`` for an HTTP proxy.
            socks_proxy: Optional ``host:port`` for a SOCKS5 proxy.
            github_url: Base URL for the GitHub API. Anything other than
                the public endpoint disables certificate verification (we
                are typically pointed at a GitHub Enterprise instance or
                a local intercepting proxy).
            client: Optional pre-built async client (used by the unit
                tests so that they can inject a mock transport).
            app_permissions: Optional permissions list for GitHub App
                tokens (purely informational, surfaced for callers).
        """
        self.pat = pat
        self.transport: str | None = None
        self.verify_ssl = True
        self.headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {pat}",
            "X-GitHub-Api-Version": version,
        }
        if not github_url:
            self.github_url = "https://api.github.com"
        else:
            self.github_url = github_url

        if http_proxy and socks_proxy:
            raise ValueError(
                "A SOCKS & HTTP proxy cannot be used at the same "
                "time! Please pass only one!"
            )

        if http_proxy:
            # We are likely using BURP, so disable SSL.
            self.verify_ssl = False
            self.transport = f"http://{http_proxy}"
        elif socks_proxy:
            self.transport = f"socks5://{socks_proxy}"

        if self.github_url != "https://api.github.com":
            self.verify_ssl = False

        if client:
            self.client = client
        else:
            self.client = httpx.AsyncClient(
                headers=self.headers,
                http2=True,
                proxy=self.transport,
                verify=self.verify_ssl,
                follow_redirects=True,
                timeout=30.0,
            )
        self.app_permissions = app_permissions

    # ---------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self) -> None:
        """Close the underlying async client."""
        await self.client.aclose()

    def is_app_token(self) -> bool:
        """Return ``True`` if the configured token is a GitHub App token."""
        return self.pat.startswith("ghs_")

    # ---------------------------------------------------------------
    # HTTP wrappers
    # ---------------------------------------------------------------
    async def call_get(
        self, url: str, params: dict | None = None, strip_auth: bool = False
    ) -> httpx.Response:
        """Issue a GET request relative to ``github_url``.

        Args:
            url: Path portion of the URL (joined onto ``github_url``).
            params: Query parameters.
            strip_auth: If ``True``, drop the ``Authorization`` header
                (used for unauthenticated raw-content fetches).

        Returns:
            The :class:`httpx.Response` from the underlying client.
        """
        request_url = self.github_url + url

        get_header = copy.deepcopy(self.headers)
        if strip_auth:
            del get_header["Authorization"]

        api_response: httpx.Response | None = None
        for _ in range(0, 5):
            try:
                logger.debug(f"Making GET API request to {request_url}!")
                api_response = await self.client.get(
                    request_url,
                    params=params,
                    headers=get_header,
                )
                break
            except Exception as e:
                logger.warning(
                    f"GET request {request_url} failed due to transport error re-trying",
                    exc_info=e,
                )
                continue

        if api_response is None:
            raise Exception(f"GET request {request_url} failed after 5 attempts")

        if not strip_auth:
            await self._check_rate_limit(api_response.headers)

        return api_response

    async def call_post(self, url: str, params: dict | None = None) -> httpx.Response:
        """Issue a POST request relative to ``github_url`` with a JSON body."""
        request_url = self.github_url + url
        logger.debug(f"Making POST API request to {request_url}!")

        api_response = await self.client.post(request_url, json=params, timeout=30)
        logger.debug(
            f"The POST request to {request_url} returned a {api_response.status_code}!"
        )

        await self._check_rate_limit(api_response.headers)

        return api_response

    async def call_patch(self, url: str, params: dict | None = None) -> httpx.Response:
        """Issue a PATCH request relative to ``github_url`` with a JSON body."""
        request_url = self.github_url + url
        logger.debug(f"Making PATCH API request to {request_url}!")

        api_response = await self.client.patch(request_url, json=params)
        logger.debug(
            f"The PATCH request to {request_url} returned a {api_response.status_code}!"
        )

        await self._check_rate_limit(api_response.headers)

        return api_response

    async def call_put(self, url: str, params: dict | None = None) -> httpx.Response:
        """Issue a PUT request relative to ``github_url`` with a JSON body."""
        request_url = self.github_url + url
        logger.debug(f"Making PUT API request to {request_url}!")

        api_response = await self.client.put(request_url, json=params)

        await self._check_rate_limit(api_response.headers)

        return api_response

    async def call_delete(self, url: str) -> httpx.Response:
        """Issue a DELETE request relative to ``github_url``."""
        request_url = self.github_url + url
        logger.debug(f"Making DELETE API request to {request_url}!")

        api_response = await self.client.delete(request_url)
        logger.debug(
            f"The POST request to {request_url} returned a {api_response.status_code}!"
        )

        await self._check_rate_limit(api_response.headers)

        return api_response

    # ---------------------------------------------------------------
    # Internal helpers (single underscore so sub-APIs can call them)
    # ---------------------------------------------------------------
    async def _check_rate_limit(self, headers) -> None:
        """Sleep until the rate-limit window resets if we are running low.

        The trigger is intentionally conservative: when fewer than 5% of
        the bucket remains we pause execution until the documented reset
        time. Yes, printing from API code is unusual; the alternative is
        propagating a rate-limit exception out of every call site which
        is much worse.
        """
        if (
            "X-Ratelimit-Remaining" in headers
            and int(headers["X-Ratelimit-Remaining"])
            < int(headers["X-RateLimit-Limit"]) // 20
            and headers["X-Ratelimit-Resource"] == "core"
        ):
            gh_date = headers["Date"]
            reset_utc = int(headers["X-Ratelimit-Reset"])
            date = datetime.strptime(gh_date, "%a, %d %b %Y %H:%M:%S %Z")
            date = date.replace(tzinfo=timezone.utc)
            reset_time = date.fromtimestamp(reset_utc, tz=timezone.utc)

            sleep_time = (reset_time - date).seconds
            sleep_time_mins = str(sleep_time // 60)

            Output.warn(
                f"Sleeping for {Output.bright(sleep_time_mins + ' minutes')} "
                "to prevent rate limit exhaustion!"
            )

            await asyncio.sleep(sleep_time + 1)

    @staticmethod
    def _verify_result(response: httpx.Response, expected_code: int) -> bool:
        """Log + return ``False`` if ``response`` does not carry the expected status."""
        if response.status_code != expected_code:
            logger.warning(
                f"Expected status code {expected_code}, but got {response.status_code}!"
            )
            logger.debug(response.text)
            return False
        return True

    async def _process_run_log(self, log_content: bytes, run_info: dict) -> dict | None:
        """Parse a workflow-run log archive and extract runner metadata.

        The zip uploaded by GitHub contains numbered text files; the
        first ``[0-9]_*`` entry holds the setup output, which is where
        the runner name / machine / labels / token permissions appear.
        """
        log_package: dict = {}
        token_permissions: dict = {}
        runner_type = None
        non_ephemeral = False
        labels: list = []
        runner_name = None
        machine_name = None
        runner_group = None

        with zipfile.ZipFile(io.BytesIO(log_content)) as runres:
            for zipinfo in runres.infolist():
                if re.match("[0-9]{1}_.*", zipinfo.filename):
                    with runres.open(zipinfo) as run_setup:
                        content = run_setup.read().decode()
                        content_lines = content.split("\n")
                        if (
                            "Image Release: https://github.com/actions/runner-images"
                            in content
                            or "Job is about to start running on the hosted runner: GitHub Actions"
                            in content
                        ) and "1ES.Pool" not in content:
                            # Larger runners look self-hosted but ship the
                            # image marker, and "Job is about to start
                            # running on hosted runner" similarly tells us
                            # this is a GitHub-hosted runner.
                            continue
                        elif (
                            "Self-hosted runners in the repository are disabled"
                            in content
                        ):
                            break
                        index = 0
                        while index < len(content_lines) and content_lines[index]:
                            line = content_lines[index]

                            if "Requested labels: " in line:
                                labels = line.split("Requested labels: ")[1].split(", ")

                            if "Runner name: " in line:
                                runner_name = line.split("Runner name: ")[1].replace(
                                    "'", ""
                                )

                            if "Machine name: " in line:
                                machine_name = line.split("Machine name: ")[1].replace(
                                    "'", ""
                                )

                            if "Runner group name:" in line:
                                runner_group = line.split("Runner group name: ")[
                                    1
                                ].replace("'", "")

                            if "Job is about to start running on" in line:
                                runner_type = line.split()[-1]
                                matches = ApiBase.RUNNERTYPE_RE.search(runner_type)
                                if matches:
                                    runner_type = matches.group(1)

                            if "GITHUB_TOKEN Permission" in line:
                                while "[endgroup]" not in content_lines[index + 1]:
                                    index += 1
                                    scope = (
                                        content_lines[index].split()[1].replace(":", "")
                                    )
                                    permission = content_lines[index].split()[2]
                                    token_permissions[scope] = permission
                                log_package["token_permissions"] = token_permissions

                            if "Cleaning the repository" in line:
                                non_ephemeral = True
                            log_package["non_ephemeral"] = non_ephemeral

                            index += 1

                        # No runner name → we picked up a pending workflow.
                        if not runner_name:
                            continue

                        log_package = {
                            "requested_labels": labels,
                            "runner_name": runner_name,
                            "machine_name": machine_name,
                            "runner_group": runner_group,
                            "runner_type": runner_type,
                            "run_id": run_info["id"],
                            "run_attempt": run_info["run_attempt"],
                            "non_ephemeral": non_ephemeral,
                            "token_permissions": token_permissions,
                        }

                    return log_package
        return None

    async def _get_full_runlog(self, log_content: bytes, run_name: str) -> str | None:
        """Return the full text of the ``0_<run_name>`` log entry, if present."""
        with zipfile.ZipFile(io.BytesIO(log_content)) as runres:
            for zipinfo in runres.infolist():
                if f"0_{run_name}" in zipinfo.filename:
                    with runres.open(zipinfo) as run_log:
                        content = run_log.read().decode()
                        return content
        return None

    async def _get_raw_file(self, repo: str, file_path: str, ref: str) -> str | None:
        """Fetch a raw file directly from ``raw.githubusercontent.com``.

        Used to dodge the API rate-limit when the target repo is public.
        Retries a small handful of times to ride out any transient
        ``RemoteProtocolError`` chunks that occur in flaky network paths.
        """
        url = f"https://raw.githubusercontent.com/{repo}/{ref}/{file_path}"
        headers = {
            "Authorization": "None",
            "Accept": "text/plain",
        }
        attempt = 0
        resp: httpx.Response | None = None
        while attempt < 3:
            try:
                resp = await self.client.get(url, headers=headers)
                break
            except httpx.RemoteProtocolError:
                attempt += 1
                await asyncio.sleep(1)
        else:
            return None

        if resp is None:
            return None
        if resp.status_code == 404:
            return None
        elif resp.status_code == 200:
            return resp.text
        return None


class SubApi:
    """Mixin-ish base class for grouped sub-APIs.

    The whole class is here to formalise the shape every sub-API has —
    a single :class:`ApiBase` reference stored on ``self._base`` — and to
    give the sub-APIs a typed home so pyright can narrow.
    """

    __slots__ = ("_base",)

    def __init__(self, base: ApiBase) -> None:
        self._base = base
