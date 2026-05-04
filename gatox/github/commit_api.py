"""Sub-API: refs, branches, commits, tree mutations, history."""

from __future__ import annotations

import base64
import logging

from gatox.github.api_base import ApiBase, SubApi
from gatox.github.gql_queries import GqlQueries

logger = logging.getLogger(__name__)


class CommitApi(SubApi):
    """Endpoints rooted at ``/repos/{r}/git/...``, ``/branches/...``, ``/commits/...``."""

    def __init__(self, base: ApiBase) -> None:
        super().__init__(base)

    async def get_repo_branch(self, repo: str, branch: str) -> int:
        """Return ``1`` if branch exists, ``0`` if not, ``-1`` on error."""
        res = await self._base.call_get(f"/repos/{repo}/branches/{branch}")
        if res.status_code == 200:
            return 1
        elif res.status_code == 404:
            return 0
        else:
            logger.warning(f"Failed to check repo for branch! ({res.status_code}")
            return -1

    async def create_branch(self, repo_name: str, branch_name: str) -> bool:
        """Branch ``branch_name`` from the repo's default head SHA."""
        resp = await self._base.call_get(f"/repos/{repo_name}")
        default_branch = resp.json()["default_branch"]
        resp = await self._base.call_get(
            f"/repos/{repo_name}/git/ref/heads/{default_branch}"
        )

        json_resp = resp.json()
        sha = json_resp["object"]["sha"]

        branch_data = {"ref": f"refs/heads/{branch_name}", "sha": sha}

        resp = await self._base.call_post(
            f"/repos/{repo_name}/git/refs", params=branch_data
        )

        if resp.status_code == 201:
            return True
        else:
            return False

    async def delete_branch(self, repo_name: str, branch_name: str) -> bool:
        """Delete ``refs/heads/{branch_name}`` on ``repo_name``."""
        resp = await self._base.call_delete(
            f"/repos/{repo_name}/git/refs/heads/{branch_name}"
        )

        if resp.status_code == 204:
            return True
        return False

    async def commit_file(
        self,
        repo_name: str,
        branch_name: str,
        file_path: str,
        file_content: bytes,
        commit_author: str = "Gato-X",
        commit_email: str = "gato-x@pwn.com",
        message: str = "Testing",
    ) -> str | None:
        """Commit a file via the contents API. Returns the new commit SHA."""
        b64_contents = base64.b64encode(file_content)
        commit_data = {
            "message": message,
            "content": b64_contents.decode("utf-8"),
            "branch": branch_name,
            "committer": {"name": commit_author, "email": commit_email},
        }

        resp = await self._base.call_put(
            f"/repos/{repo_name}/contents/{file_path}", params=commit_data
        )

        if resp.status_code == 201:
            resp_json = resp.json()
            return resp_json["commit"]["sha"]
        else:
            logger.debug(resp.status_code)
            logger.debug(resp.text)
            return None

    async def commit_workflow(
        self,
        repo_name: str,
        target_branch: str,
        workflow_contents: bytes,
        file_name: str,
        commit_author: str = "Gato-X",
        commit_email: str = "Gato-X@pwn.com",
        message: str = "Testing",
    ) -> str | None:
        """Push a workflow file as a commit, deleting any other workflows.

        Steps:

        1. Resolve the default branch and its head SHA.
        2. Pull the recursive tree for that head.
        3. Build a new tree that *only* contains the supplied workflow
           file under ``.github/workflows/`` (other workflow blobs are
           explicitly removed).
        4. Push a commit + a new branch ref for ``target_branch``.

        Returns the new commit SHA on success, ``None`` otherwise.
        """
        r = await self._base.call_get(f"/repos/{repo_name}")
        if self._base._verify_result(r, 200) is False:
            return None
        default_branch = r.json()["default_branch"]

        r = await self._base.call_get(f"/repos/{repo_name}/commits/{default_branch}")
        if self._base._verify_result(r, 200) is False:
            return None
        latest_commit_sha = r.json()["sha"]

        r = await self._base.call_get(
            f"/repos/{repo_name}/git/commits/{latest_commit_sha}"
        )
        if self._base._verify_result(r, 200) is False:
            return None
        tree_sha = r.json()["tree"]["sha"]

        r = await self._base.call_get(
            f"/repos/{repo_name}/git/trees/{tree_sha}", params={"recursive": "1"}
        )
        if self._base._verify_result(r, 200) is False:
            return None

        tree_info = r.json()
        base_sha = tree_info["sha"]
        tree = tree_info["tree"]

        existing_files = (
            item
            for item in tree
            if ".github/workflows" in item["path"] and item["type"] == "blob"
        )

        new_workflow_file_content = base64.b64encode(workflow_contents).decode()

        r = await self._base.call_post(
            f"/repos/{repo_name}/git/blobs",
            params={"content": new_workflow_file_content, "encoding": "base64"},
        )
        if self._base._verify_result(r, 201) is False:
            return None

        new_tree: list = [
            {
                "path": f".github/workflows/{file_name}",
                "mode": "100644",
                "type": "blob",
                "sha": r.json()["sha"],
            }
        ]

        for existing in existing_files:
            # Don't delete the same file - this happens if the workflow
            # already exists (e.g. a test.yml file).
            if existing["path"] == f".github/workflows/{file_name}":
                continue

            new_tree.append(
                {
                    "path": existing["path"],
                    "mode": existing["mode"],
                    "type": existing["type"],
                    "sha": None,
                }
            )

        r = await self._base.call_post(
            f"/repos/{repo_name}/git/trees",
            params={"base_tree": base_sha, "tree": new_tree},
        )
        if self._base._verify_result(r, 201) is False:
            return None
        new_tree_sha = r.json()["sha"]

        r = await self._base.call_post(
            f"/repos/{repo_name}/git/commits",
            params={
                "message": message,
                "tree": new_tree_sha,
                "parents": [latest_commit_sha],
                "author": {"name": commit_author, "email": commit_email},
            },
        )
        new_commit_sha = r.json()["sha"]

        r = await self._base.call_post(
            f"/repos/{repo_name}/git/refs",
            params={"sha": new_commit_sha, "ref": f"refs/heads/{target_branch}"},
        )
        if self._base._verify_result(r, 201) is False:
            return None

        return new_commit_sha

    async def create_workflow_on_branch(
        self,
        repo: str,
        branch: str,
        filename: str,
        content: str,
        commit_message: str = "[skip ci] Workflow",
        commit_author: str = "Gato-X",
        commit_email: str = "gato-x@pwn.com",
    ) -> str | bool | None:
        """Create or update a workflow file on a specific branch.

        If ``branch`` does not yet exist it is branched off the default
        branch first; either way the file is committed via the contents
        API.
        """
        # Pull repo info to find the default branch.
        repo_info = await self._base.repo.get_repository(repo)
        if not repo_info:
            return False

        default_branch = repo_info.get("default_branch", "main")

        branch_info = await self._base.call_get(
            f"/repos/{repo}/git/ref/heads/{default_branch}"
        )
        if branch_info.status_code != 200:
            return False

        default_sha = branch_info.json()["object"]["sha"]

        create_branch_params = {"ref": f"refs/heads/{branch}", "sha": default_sha}

        await self._base.call_post(
            f"/repos/{repo}/git/refs", params=create_branch_params
        )
        # Don't check status code here — branch might already exist.

        # Allow the ref to settle.
        import asyncio

        await asyncio.sleep(1)

        workflow_path = f".github/workflows/{filename}"

        commit_sha = await self.commit_file(
            repo_name=repo,
            branch_name=branch,
            file_path=workflow_path,
            file_content=content.encode(),
            commit_author=commit_author,
            commit_email=commit_email,
            message=commit_message,
        )

        return commit_sha

    async def backtrack_head(
        self, repo_name: str, ref_name: str, commit_depth: int
    ) -> bool:
        """Force-reset ``ref_name`` to its ``commit_depth``-th ancestor.

        This is the equivalent of::

            git reset --hard HEAD~<commit_depth>
            git push --force

        and is used to remove attack payloads from a PR branch when
        cleaning up.
        """
        params = {"sha": ref_name, "per_page": commit_depth + 1}

        resp = await self._base.call_get(f"/repos/{repo_name}/commits", params=params)

        if resp.status_code == 200:
            commits = resp.json()
            target = commits[commit_depth]["sha"]
        else:
            return False

        resp = await self._base.call_patch(
            f"/repos/{repo_name}/git/refs/heads/{ref_name}",
            params={"sha": target, "force": True},
        )

        if resp.status_code == 200:
            return True
        else:
            return False

    async def get_file_last_updated(
        self, repo_name: str, file_path: str
    ) -> tuple[str, str, str]:
        """Return ``(date, author, sha)`` for the latest commit touching ``file_path``."""
        resp = await self._base.call_get(
            f"/repos/{repo_name}/commits", params={"path": file_path, "per_page": 1}
        )

        commit_date = resp.json()[0]["commit"]["author"]["date"]
        commit_author = resp.json()[0]["commit"]["author"]["name"]
        commit_sha = resp.json()[0]["sha"]

        return commit_date, commit_author, commit_sha

    async def get_commit_merge_date(self, repo: str, sha: str) -> str | None:
        """Return the merge timestamp of the PR that introduced ``sha``, if any."""
        query = {
            "query": GqlQueries.GET_PR_MERGED,
            "variables": {
                "sha": sha,
                "repo": repo.split("/")[1],
                "owner": repo.split("/")[0],
            },
        }

        r = await self._base.call_post("/graphql", params=query)
        if r.status_code == 200:
            response = r.json()

            if not response["data"]["repository"]:
                return None

            if not response["data"]["repository"]["commit"]["associatedPullRequests"][
                "edges"
            ]:
                return None

            pr_info = response["data"]["repository"]["commit"][
                "associatedPullRequests"
            ]["edges"][0]["node"]

            if pr_info["merged"]:
                return pr_info["mergedAt"]
        return None
