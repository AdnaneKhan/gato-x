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

from gatox.cli.output import Output

from .webshell_utils import WebShellUtils


class RepositoryManager:
    """Manages repository operations for WebShell attacks."""

    def __init__(self, api, timeout: int = 30):
        self.api = api
        self.timeout = timeout

    async def setup_target_repository(
        self,
        target_repo: str,
        target_branch: str,
        source_branch: str,
        author_name: str,
        author_email: str,
    ) -> str | None:
        """
        Set up the target repository by forking and preparing the attack branch.

        Args:
            target_repo: Target repository to fork
            target_branch: Target branch to check
            source_branch: Source branch for the attack
            author_name: Commit author name
            author_email: Commit author email

        Returns:
            Fork repository name or None if failed
        """
        # Check if target branch exists
        if not await self._validate_target_branch(target_repo, target_branch):
            return None

        # Fork the repository
        repo_name = await self._fork_repository(target_repo)
        if not repo_name:
            return None

        # Wait for fork to be ready
        if not await WebShellUtils.wait_for_repository_ready(
            self.api, repo_name, self.timeout
        ):
            return None

        # Handle branch conflicts
        if not await self._handle_branch_conflicts(repo_name, source_branch):
            return None

        return repo_name

    async def deploy_workflow(
        self,
        repo_name: str,
        source_branch: str,
        workflow_content: bytes,
        yaml_name: str,
        commit_author: str,
        commit_email: str,
    ) -> bool:
        """
        Deploy the attack workflow to the repository.

        Args:
            repo_name: Repository name
            source_branch: Branch to commit to
            workflow_content: Workflow file content
            yaml_name: Name of the workflow file
            commit_author: Commit author name
            commit_email: Commit author email

        Returns:
            True if successful, False otherwise
        """
        status = await self.api.commit_workflow(
            repo_name,
            source_branch,
            workflow_content,
            f"{yaml_name}.yml",
            commit_author=commit_author,
            commit_email=commit_email,
        )

        if not status:
            Output.error("Failed to commit RoR workflow to fork!")
            return False

        return True

    async def create_pull_request(
        self,
        repo_name: str,
        source_branch: str,
        target_repo: str,
        target_branch: str,
        pr_title: str,
    ) -> str | None:
        """
        Create a draft pull request for the attack.

        Args:
            repo_name: Fork repository name
            source_branch: Source branch
            target_repo: Target repository
            target_branch: Target branch
            pr_title: Pull request title

        Returns:
            Pull request URL or None if failed
        """
        pull_url = await self.api.create_pull_request(
            repo_name,
            source_branch,
            target_repo,
            target_branch,
            pr_body="Gato-X CI/CD Test",
            pr_title=pr_title,
            draft=True,
        )

        if pull_url:
            Output.result(f"Successfully created draft pull request: {pull_url}")
            return pull_url
        else:
            Output.error("Failed to create draft pull request!")
            return None

    async def close_pull_request(self, repo_name: str, source_branch: str) -> bool:
        """
        Close the pull request by backing out the commit.

        Args:
            repo_name: Repository name
            source_branch: Source branch

        Returns:
            True if successful, False otherwise
        """
        close_res = await self.api.backtrack_head(repo_name, source_branch, 1)
        if close_res:
            Output.result("Successfully closed pull request!")
            return True
        else:
            Output.error("Failed to close pull request!")
            return False

    async def _validate_target_branch(
        self, target_repo: str, target_branch: str
    ) -> bool:
        """Validate that the target branch exists."""
        res = await self.api.get_repo_branch(target_repo, target_branch)
        if res == 0:
            Output.error(f"Target branch, {target_branch}, does not exist!")
            return False
        elif res == -1:
            Output.error("Failed to check for target branch!")
            return False
        return True

    async def _fork_repository(self, target_repo: str) -> str | None:
        """Fork the target repository."""
        repo_name = await self.api.fork_repository(target_repo)
        if not repo_name:
            Output.error("Error while forking repository!")
            return None
        return repo_name

    async def _handle_branch_conflicts(
        self, repo_name: str, source_branch: str
    ) -> bool:
        """Handle conflicts when the source branch already exists in the fork."""
        branch_exists = await self.api.get_repo_branch(repo_name, source_branch)

        if branch_exists == 1:
            Output.warn(f"Branch '{source_branch}' already exists in the fork!")
            Output.warn("Options:")
            Output.warn("  1. Delete the existing branch and recreate it")
            Output.warn("  2. Exit to handle manually")

            while True:
                user_choice = input("Enter your choice (1 or 2): ").strip()
                if user_choice == "1":
                    Output.info(f"Deleting existing branch '{source_branch}'...")
                    delete_success = await self.api.delete_branch(
                        repo_name, source_branch
                    )
                    if delete_success:
                        Output.result(f"Successfully deleted branch '{source_branch}'")
                        return True
                    else:
                        Output.error(f"Failed to delete branch '{source_branch}'!")
                        return False
                elif user_choice == "2":
                    Output.info("Exiting to allow manual branch handling...")
                    return False
                else:
                    Output.error("Invalid choice. Please enter 1 or 2.")
        elif branch_exists == -1:
            Output.error(f"Failed to check if branch '{source_branch}' exists in fork!")
            return False

        return True
