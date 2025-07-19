"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import asyncio
import datetime
from typing import Optional, Callable, Any

from gatox.cli.output import Output


class WebShellUtils:
    """Utility functions for WebShell operations."""

    @staticmethod
    def get_current_timestamp() -> str:
        """Generate current timestamp in ISO format."""
        return (
            datetime.datetime.now(tz=datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )

    @staticmethod
    async def poll_with_timeout(
        condition_func: Callable[[], Any],
        timeout: int,
        sleep_interval: int = 1,
        success_condition: Optional[Callable[[Any], bool]] = None,
    ) -> Any:
        """
        Generic polling function with timeout.

        Args:
            condition_func: Function to poll
            timeout: Maximum time to wait in seconds
            sleep_interval: Sleep interval between polls
            success_condition: Function to check if result is successful

        Returns:
            Result of condition_func or None if timeout
        """
        if success_condition is None:
            def success_condition(x):
                return bool(x)

        for _ in range(timeout):
            result = await condition_func()
            if success_condition(result):
                return result
            await asyncio.sleep(sleep_interval)

        return None

    @staticmethod
    async def wait_for_workflow(
        api,
        repo: str,
        commit_sha: str,
        workflow_name: str,
        time_after: str,
        timeout: int,
    ) -> Optional[int]:
        """
        Wait for a workflow to appear and return its ID.

        Args:
            api: API instance
            repo: Repository name
            commit_sha: Commit SHA to check
            workflow_name: Name of the workflow
            time_after: Time filter for workflow search
            timeout: Maximum time to wait

        Returns:
            Workflow ID or None if not found
        """

        async def check_workflow():
            return await api.get_recent_workflow(
                repo, commit_sha, workflow_name, time_after=time_after
            )

        def is_workflow_found(workflow_id):
            if workflow_id == -1:
                Output.error("Failed to find the created workflow!")
                return False
            return workflow_id > 0

        workflow_id = await WebShellUtils.poll_with_timeout(
            check_workflow, timeout, success_condition=is_workflow_found
        )

        if workflow_id is None:
            Output.error("Failed to find the created workflow!")
            return None

        return workflow_id

    @staticmethod
    async def wait_for_workflow_completion(
        api, repo: str, workflow_id: int, timeout: int
    ) -> Optional[int]:
        """
        Wait for a workflow to complete.

        Args:
            api: API instance
            repo: Repository name
            workflow_id: Workflow ID to monitor
            timeout: Maximum time to wait

        Returns:
            Workflow status or None if timeout
        """

        async def check_status():
            return await api.get_workflow_status(repo, workflow_id)

        def is_complete(status):
            return status == -1 or status == 1

        status = await WebShellUtils.poll_with_timeout(
            check_status, timeout, success_condition=is_complete
        )

        if status is None:
            Output.error(
                "The workflow is incomplete but hit the timeout, "
                "check the C2 repository manually to debug!"
            )

        return status

    @staticmethod
    async def wait_for_repository_ready(api, repo_name: str, timeout: int) -> bool:
        """
        Wait for a forked repository to be ready.

        Args:
            api: API instance
            repo_name: Repository name
            timeout: Maximum time to wait

        Returns:
            True if repository is ready, False otherwise
        """

        async def check_repo():
            return await api.get_repository(repo_name)

        status = await WebShellUtils.poll_with_timeout(check_repo, timeout)

        if status:
            Output.result(f"Successfully created fork: {repo_name}!")
            await asyncio.sleep(5)  # Additional wait for stability
            return True
        else:
            Output.error(f"Forked repository not found after {timeout} seconds!")
            return False

    @staticmethod
    async def wait_for_runners(api, c2_repo: str, timeout: int) -> Optional[list]:
        """
        Wait for runners to connect to C2 repository.

        Args:
            api: API instance
            c2_repo: C2 repository name
            timeout: Maximum time to wait

        Returns:
            List of runners or None if timeout
        """

        async def check_runners():
            return await api.get_repo_runners(c2_repo)

        runners = await WebShellUtils.poll_with_timeout(check_runners, timeout)

        if runners:
            Output.owned("Runner connected to C2 repository!")
            return runners
        else:
            Output.warn("No runners connected to C2 repository!")
            return None
