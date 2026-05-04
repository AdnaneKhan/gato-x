"""Sub-API: Actions runners, workflow runs, logs, artifacts, environments, dispatches."""

from __future__ import annotations

import io
import logging
import zipfile
from datetime import datetime, timedelta

from gatox.github.api_base import ApiBase, SubApi

logger = logging.getLogger(__name__)


class ActionApi(SubApi):
    """Endpoints rooted at ``/repos/{r}/actions/...`` plus environment / dispatch."""

    def __init__(self, base: ApiBase) -> None:
        super().__init__(base)

    # ---------------------------------------------------------------
    # Runners
    # ---------------------------------------------------------------
    async def get_repo_runners(self, full_name: str) -> list:
        """Return the runners attached to ``full_name`` (empty list on 403)."""
        runners = await self._base.call_get(f"/repos/{full_name}/actions/runners")

        if runners.status_code == 200:
            runner_list = runners.json()["runners"]
            return runner_list
        elif runners.status_code == 403:
            logger.debug(
                f"Unable to query runners for {full_name}! This is likely due to the"
                " PAT permission level!"
            )

        return []

    # ---------------------------------------------------------------
    # Workflow runs
    # ---------------------------------------------------------------
    async def retrieve_run_logs(
        self, repo_name: str, workflows: list | set | None = None
    ):
        """Walk recent workflow runs and parse their setup logs.

        For each (branch, workflow) pair we sample at most three recent
        completed runs and download / parse their attempt logs to
        extract runner metadata (name / machine / labels / token
        permissions). The first non-ephemeral runner short-circuits the
        loop.

        Returns:
            ``dict_values`` of unique ``machine_name:runner_name``
            log packages.
        """
        if workflows is None:
            workflows = []
        start_date = datetime.now() - timedelta(days=60)
        runs: list = []

        for workflow in workflows:
            run_result = await self._base.call_get(
                f"/repos/{repo_name}/actions/workflows/{workflow}/runs",
                params={
                    "per_page": "3",
                    "status": "completed",
                    "exclude_pull_requests": "true",
                    "created": f">{start_date.isoformat()}",
                },
            )

            if run_result.status_code == 200:
                runs.extend(run_result.json()["workflow_runs"])

        run_logs: dict = {}
        names: set = set()
        total_attempts = 0

        if runs:
            logger.debug(f"Enumerating runs within {repo_name}")
        for run in runs:
            # Look at at most 10 logs. If none have a non-ephemeral
            # runner by then, more won't help — and very large repos
            # with matrix builds and reusable workflows can have huge
            # zips that waste a lot of time.
            if total_attempts > 10:
                break

            if run["conclusion"] != "success" and run["conclusion"] != "failure":
                continue

            workflow_key = f"{run['head_branch']}:{run['path']}"
            if workflow_key in names:
                continue
            names.add(workflow_key)
            run_log = await self._base.call_get(
                f"/repos/{repo_name}/actions/runs/{run['id']}/"
                f"attempts/{run['run_attempt']}/logs"
            )

            if run_log.status_code == 200:
                try:
                    parsed = await self._base._process_run_log(run_log.content, run)
                    if parsed:
                        key = f"{parsed['machine_name']}:{parsed['runner_name']}"
                        run_logs[key] = parsed

                        if parsed["non_ephemeral"]:
                            return run_logs.values()
                except Exception:
                    logger.warning(
                        f"Failed to process run log for {repo_name} run "
                        f"{run['id']} attempt {run['run_attempt']}!"
                    )
            elif run_log.status_code == 410:
                break
            else:
                logger.debug(
                    f"Call to retrieve run logs from {repo_name} run "
                    f"{run['id']} attempt {run['run_attempt']} returned "
                    f"{run_log.status_code}!"
                )

            total_attempts += 1

        return run_logs.values()

    async def parse_workflow_runs(self, repo_name: str) -> int | None:
        """Return the total run count for ``repo_name`` or ``None`` on error."""
        runs = await self._base.call_get(f"/repos/{repo_name}/actions/runs")

        if runs.status_code == 200:
            return runs.json()["total_count"]
        else:
            logger.warning("Unable to query workflow runs.")

        return None

    async def get_recent_workflow(
        self, repo_name: str, sha: str, file_name: str, time_after: str | None = None
    ) -> int:
        """Return the run id matching ``sha`` and ``file_name``.

        Returns ``0`` if no matching run is found and ``-1`` on error.
        """
        params: dict = {"head_sha": sha}

        if time_after:
            params["created"] = time_after

        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs", params=params
        )

        if req.status_code != 200:
            logger.warning("Unable to query workflow runs.")
            return -1

        data = req.json()

        if data["total_count"] == 0:
            return 0

        for workflow in data["workflow_runs"]:
            if f".github/workflows/{file_name}.yml" in workflow["path"]:
                return workflow["id"]

        return 0

    async def get_workflow_status(self, repo_name: str, workflow_id: int) -> int:
        """Return ``1`` for success, ``0`` for pending, ``-1`` for failure / error."""
        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}"
        )

        if req.status_code != 200:
            logger.warning("Unable to query the workflow.")
            return -1

        data = req.json()

        if data.get("status", "queued") in ["queued", "in_progress"]:
            return 0
        return 1 if data.get("conclusion", "failure") == "success" else -1

    async def delete_workflow_run(self, repo_name: str, workflow_id: int) -> bool:
        """Delete a previous workflow run."""
        req = await self._base.call_delete(
            f"/repos/{repo_name}/actions/runs/{workflow_id}"
        )

        return req.status_code == 204

    # ---------------------------------------------------------------
    # Logs
    # ---------------------------------------------------------------
    async def download_workflow_logs(self, repo_name: str, workflow_id: int) -> bool:
        """Download a run log archive to ``{workflow_id}.zip`` on disk."""
        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/logs"
        )

        if req.status_code != 200:
            return False

        with open(f"{workflow_id}.zip", "wb+") as f:
            f.write(req.content)
        return True

    async def retrieve_workflow_log(
        self, repo_name: str, workflow_id: int, job_name: str
    ) -> str | bool | None:
        """Return the text of the ``0_<job_name>`` entry in the run log."""
        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/logs"
        )

        if req.status_code != 200:
            return False

        return await self._base._get_full_runlog(req.content, job_name)

    # ---------------------------------------------------------------
    # Artifacts
    # ---------------------------------------------------------------
    async def retrieve_workflow_artifact(
        self, repo_name: str, workflow_id: int
    ) -> dict:
        """Download the *first* artifact and return its files in-memory.

        Use only for small artifacts — the zip is read into memory.
        """
        files: dict = {}

        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/artifacts"
        )
        if req.status_code != 200:
            return files

        artifacts = req.json().get("artifacts", [])

        if artifacts:
            download_url = artifacts[0]["archive_download_url"]

            archive = await self._base.call_get(
                download_url.replace("https://api.github.com", "")
            )

            with zipfile.ZipFile(io.BytesIO(archive.content)) as artifact:
                for zipinfo in artifact.infolist():
                    with artifact.open(zipinfo) as run_log:
                        content = run_log.read()
                        files[zipinfo.filename] = content

        return files

    async def retrieve_all_workflow_artifacts(
        self, repo_name: str, workflow_id: int
    ) -> dict:
        """Return ``{artifact_name: {filename: bytes}}`` for the run."""
        result: dict = {}

        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/artifacts"
        )
        if req.status_code != 200:
            return result

        for artifact in req.json().get("artifacts", []):
            download_url = artifact["archive_download_url"]
            archive = await self._base.call_get(
                download_url.replace("https://api.github.com", "")
            )
            files: dict = {}
            with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
                for zipinfo in zf.infolist():
                    with zf.open(zipinfo) as f:
                        files[zipinfo.filename] = f.read()
            result[artifact["name"]] = files

        return result

    async def download_workflow_artifact(
        self, repo_name: str, workflow_id: int, destination: str
    ) -> str | bool:
        """Download the first artifact and save it to ``destination``."""
        req = await self._base.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/artifacts"
        )
        if req.status_code != 200:
            return False

        artifacts = req.json().get("artifacts", [])
        download_url = artifacts[0]["archive_download_url"]

        archive = await self._base.call_get(
            download_url.replace("https://api.github.com", "")
        )

        with open(destination, "wb") as f:
            f.write(archive.content)

            return destination

        return False

    # ---------------------------------------------------------------
    # Environments / dispatches
    # ---------------------------------------------------------------
    async def get_all_environment_protection_rules(self, repo_name: str) -> list[str]:
        """Return env names that have a ``required_reviewers`` rule."""
        response = await self._base.call_get(f"/repos/{repo_name}/environments")

        all_protection_rules: list[str] = []

        if response.status_code == 200:
            all_environments = response.json()

            for environment in all_environments["environments"]:
                protection_rules = environment.get("protection_rules", [])
                all_protection_rules.extend(
                    [
                        environment["name"]
                        for rule in protection_rules
                        if rule["type"] == "required_reviewers"
                    ]
                )

        return all_protection_rules

    async def issue_dispatch(
        self,
        repo_name: str,
        target_workflow: str,
        target_branch: str,
        dispatch_inputs: dict,
    ) -> bool:
        """Trigger a ``workflow_dispatch`` event on ``target_workflow``."""
        r = await self._base.call_post(
            f"/repos/{repo_name}/actions/workflows/{target_workflow}/dispatches",
            params={"ref": target_branch, "inputs": dispatch_inputs},
        )

        return r.status_code == 204
