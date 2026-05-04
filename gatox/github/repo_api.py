"""Sub-API: repository-scoped reads and writes.

This is the largest sub-API by surface area. It owns:

* repository metadata (`get_repository`, `delete_repository`,
  `fork_repository`),
* file-content reads (workflow YAMLs, raw actions, single files),
* repo-owned secrets (repo-level, environment, and the repo's view of
  org secrets),
* collaborator / deploy-key writes,
* pull-request and issue-comment plumbing used by the attack drivers.

Workflow-run state, runners, artifacts and dispatches live on
:class:`gatox.github.action_api.ActionApi`. Branch / commit / tree
mutations live on :class:`gatox.github.commit_api.CommitApi`.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime, timedelta, timezone

from gatox.github.api_base import ApiBase, SubApi
from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class RepoApi(SubApi):
    """Repo-level operations: reads, secrets, PRs/issues, collaborators."""

    def __init__(self, base: ApiBase) -> None:
        super().__init__(base)

    # ---------------------------------------------------------------
    # Repository metadata
    # ---------------------------------------------------------------
    async def get_repository(self, repository: str) -> dict | None:
        """Return ``GET /repos/{repository}`` JSON or ``None``."""
        result = await self._base.call_get(f"/repos/{repository}")

        if result.status_code == 200:
            return result.json()
        return None

    async def delete_repository(self, repo_name: str) -> bool:
        """Delete the repo if the token has admin rights. Returns success bool."""
        result = await self._base.call_delete(f"/repos/{repo_name}")

        if result.status_code == 204:
            logger.info(f"Successfully deleted {repo_name}!")
        else:
            logger.warning(f"Unable to delete repository {repo_name}!")
            return False

        return True

    async def fork_repository(self, repo_name: str) -> str | bool:
        """Fork ``repo_name`` and return ``"owner/forked"``. ``False`` on failure."""
        post_params = {"default_branch_only": True}

        result = await self._base.call_post(
            f"/repos/{repo_name}/forks", params=post_params
        )

        if result.status_code == 202:
            fork_info = result.json()
            return fork_info["full_name"]
        elif result.status_code == 403:
            logger.warning("Forking this repository is forbidden!")
            return False
        elif result.status_code == 404:
            logger.warning("Unable to fork due to 404, ensure repository exists.")
            return False
        else:
            logger.warning("Repository fork failed!")
            return False

    # ---------------------------------------------------------------
    # File / workflow content reads
    # ---------------------------------------------------------------
    async def retrieve_workflow_ymls(self, repo_name: str) -> list[Workflow]:
        """Return all ``.yml`` / ``.yaml`` workflows in ``.github/workflows``."""
        ymls: list[Workflow] = []

        resp = await self._base.call_get(
            f"/repos/{repo_name}/contents/.github/workflows"
        )

        if resp.status_code == 200:
            objects = resp.json()
            semaphore = asyncio.Semaphore(50)

            async def fetch_file(file):
                async with semaphore:
                    resp_file = await self._base.call_get(
                        f"/repos/{repo_name}/contents/{file['path']}"
                    )
                    if resp_file.status_code == 200:
                        resp_data = resp_file.json()
                        if "content" in resp_data:
                            file_data = base64.b64decode(resp_data["content"])
                            return Workflow(repo_name, file_data, file["name"])
                    return None

            tasks = [
                asyncio.create_task(fetch_file(file))
                for file in objects
                if file["type"] == "file"
                and (file["name"].endswith(".yml") or file["name"].endswith(".yaml"))
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ymls = [wf for wf in results if isinstance(wf, Workflow)]

        return ymls

    async def retrieve_workflow_ymls_ref(
        self, repo_name: str, ref: str
    ) -> list[Workflow]:
        """Same as :meth:`retrieve_workflow_ymls` but at a specific ref/SHA."""
        ymls: list[Workflow] = []
        objects: list = []

        resp = await self._base.call_get(
            f"/repos/{repo_name}/contents/.github/workflows",
            params={"ref": ref},
        )

        if resp.status_code == 200:
            objects = resp.json()
        else:
            logger.warning(
                f"Failed to retrieve workflows from {repo_name} at ref {ref}!"
            )

        if objects:
            semaphore = asyncio.Semaphore(50)

            async def fetch_file(file):
                async with semaphore:
                    resp_file = await self._base.call_get(
                        f"/repos/{repo_name}/contents/{file['path']}",
                        params={"ref": ref},
                    )
                    if resp_file.status_code == 200:
                        resp_data = resp_file.json()
                        if "content" in resp_data:
                            file_data = base64.b64decode(resp_data["content"])
                            return Workflow(repo_name, file_data, file["name"])
                    return None

            tasks = [
                asyncio.create_task(fetch_file(file))
                for file in objects
                if file["type"] == "file"
                and (file["name"].endswith(".yml") or file["name"].endswith(".yaml"))
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ymls = [wf for wf in results if isinstance(wf, Workflow)]

        return ymls

    async def retrieve_repo_file(
        self, repo_name: str, file_path: str, ref: str, public: bool = False
    ) -> Workflow | None:
        """Fetch a single file from the repo at ``ref`` and wrap as ``Workflow``.

        For public repos the raw.githubusercontent.com endpoint is used
        first to save rate-limit budget.
        """
        file_data: bytes | str | None = None

        if public:
            file_data = await self._base._get_raw_file(repo_name, file_path, ref)
        else:
            resp = await self._base.call_get(
                f"/repos/{repo_name}/contents/{file_path}", params={"ref": ref}
            )
            if resp.status_code == 200:
                resp_data = resp.json()
                if "content" in resp_data:
                    file_data = base64.b64decode(resp_data["content"])

        if file_data:
            return Workflow(
                repo_name,
                file_data,
                file_path.rsplit("/", 1)[-1],
                default_branch=ref,
                special_path=file_path,
            )
        return None

    async def retrieve_workflow_yml(
        self, repo_name: str, workflow_name: str
    ) -> Workflow:
        """Fetch a single workflow yml by name. Raises ``ValueError`` on miss."""
        resp = await self._base.call_get(
            f"/repos/{repo_name}/contents/.github/workflows/{workflow_name}"
        )

        if resp.status_code == 200:
            resp_data = resp.json()
            if "content" in resp_data:
                file_data = base64.b64decode(resp_data["content"])
                return Workflow(repo_name, file_data, workflow_name)
        raise ValueError(
            f"Failed to retrieve workflow {workflow_name} from {repo_name}!"
        )

    async def retrieve_raw_action(
        self, repo: str, file_path: str, ref: str
    ) -> str | None:
        """Fetch an action yaml file, with raw fallback to authenticated."""
        if file_path.endswith(".yml") or file_path.endswith(".yaml"):
            file_path = file_path.replace("//", "/")
            paths = [file_path]
        else:
            if file_path and not file_path.endswith("/"):
                file_path += "/"
            elif file_path.endswith("//"):
                file_path = file_path.replace("//", "/")
            paths = [f"{file_path}action.yml", f"{file_path}action.yaml"]

        # Try the raw request first (no rate limit).
        for path in paths:
            res = await self._base._get_raw_file(repo, path, ref)
            if res:
                return res

        # Then drop to auth if it fails (consumes RL).
        for path in paths:
            resp = await self._base.call_get(
                f"/repos/{repo}/contents/{path}", params={"ref": ref}
            )

            if resp.status_code == 200:
                resp_data = resp.json()
                if "content" in resp_data:
                    file_data = base64.b64decode(resp_data["content"]).decode()
                    return file_data

        return None

    # ---------------------------------------------------------------
    # Secrets
    # ---------------------------------------------------------------
    async def get_secrets(self, repo_name: str) -> list[dict]:
        """List repo-level Actions secrets (paginated)."""
        secrets: list[dict] = []
        page = 1
        per_page = 100

        while True:
            params = {"page": page, "per_page": per_page}
            resp = await self._base.call_get(
                f"/repos/{repo_name}/actions/secrets", params=params
            )
            if resp.status_code == 200:
                secrets_response = resp.json()
                page_secrets = secrets_response["secrets"]
                if not page_secrets:
                    break
                secrets.extend(page_secrets)
                if len(page_secrets) < per_page:
                    break
                page += 1
            else:
                break

        return secrets

    async def get_environment_secrets(
        self, repo_name: str, environment_name: str
    ) -> list[dict]:
        """List secrets attached to a specific repo environment."""
        secrets: list[dict] = []
        page = 1
        per_page = 100

        environment_name = environment_name.replace("/", "%2F")
        while True:
            params = {"page": page, "per_page": per_page}
            resp = await self._base.call_get(
                f"/repos/{repo_name}/environments/{environment_name}/secrets",
                params=params,
            )
            if resp.status_code == 200:
                secrets_response = resp.json()
                page_secrets = secrets_response["secrets"]
                if not page_secrets:
                    break
                secrets.extend(page_secrets)
                if len(page_secrets) < per_page:
                    break
                page += 1
            else:
                break

        return secrets

    async def get_repo_org_secrets(self, repo_name: str) -> list[dict]:
        """List org-level secrets accessible to ``repo_name`` via Actions."""
        secrets: list[dict] = []
        page = 1
        per_page = 100

        while True:
            params = {"page": page, "per_page": per_page}
            resp = await self._base.call_get(
                f"/repos/{repo_name}/actions/organization-secrets", params=params
            )
            if resp.status_code == 200:
                secrets_response = resp.json()
                page_secrets = secrets_response["secrets"]
                if not page_secrets:
                    break
                secrets.extend(page_secrets)
                if len(page_secrets) < per_page:
                    break
                page += 1
            else:
                break

        return secrets

    # ---------------------------------------------------------------
    # PRs / issues
    # ---------------------------------------------------------------
    async def create_fork_pr(
        self,
        target_repo: str,
        source_user: str,
        source_branch: str,
        target_branch: str,
        pr_title: str,
    ) -> str | None:
        """Open a draft PR from ``source_user:source_branch`` into ``target_repo``."""
        pr_params = {
            "title": pr_title,
            "head": f"{source_user}:{source_branch}",
            "base": f"{target_branch}",
            "body": "This is a test pull request created for CI/CD"
            " vulnerability testing purposes.",
            "maintainer_can_modify": False,
            "draft": True,
        }

        result = await self._base.call_post(
            f"/repos/{target_repo}/pulls", params=pr_params
        )

        if result.status_code == 201:
            details = result.json()
            return details["html_url"]
        else:
            logger.warning(
                f"Failed to create PR for fork,"
                f" the status code was: {result.status_code}!"
            )
            return None

    async def create_pull_request(
        self,
        source_repo: str,
        source_branch: str,
        target_repo: str,
        target_banch: str,
        pr_body: str = "",
        pr_title: str = "CI Test",
        draft: bool = True,
    ) -> str | bool:
        """Open a (default: draft) cross-repo PR. ``False`` on failure."""
        params = {
            "title": pr_title,
            "body": pr_body,
            "head": source_branch,
            "base": target_banch,
            "head_repo": source_repo,
            "draft": draft,
        }

        response = await self._base.call_post(
            f"/repos/{target_repo}/pulls", params=params
        )

        if response.status_code == 201:
            return response.json()["html_url"]
        else:
            return False

    async def get_issue_comments(self, repo_name: str, target_pr: int) -> list[dict]:
        """Return up to 5 comments on ``target_pr`` from the last minute."""
        since = (
            (datetime.now(timezone.utc) - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
        )
        params = {"per_page": 5, "since": since + "Z"}

        r = await self._base.call_get(
            f"/repos/{repo_name}/issues/{target_pr}/comments", params=params
        )

        return r.json()

    # ---------------------------------------------------------------
    # Collaborator / deploy-key writes
    # ---------------------------------------------------------------
    async def invite_collaborator(
        self, repo: str, username: str, permission: str = "admin"
    ) -> bool:
        """Invite ``username`` as a collaborator on ``repo``."""
        params = {"permission": permission}

        response = await self._base.call_put(
            f"/repos/{repo}/collaborators/{username}", params=params
        )
        return response.status_code in [201, 204]

    async def create_deploy_key(
        self, repo: str, title: str, key: str, read_only: bool = True
    ) -> bool:
        """Add an SSH deploy key to ``repo``."""
        params = {"title": title, "key": key, "read_only": read_only}

        response = await self._base.call_post(f"/repos/{repo}/keys", params=params)
        return response.status_code == 201
