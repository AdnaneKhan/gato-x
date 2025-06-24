import tempfile
import os
import subprocess
import logging
import asyncio

from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class Git:
    """Git handler for cloning repositories and checking workflows."""

    def __init__(
        self,
        pat: str,
        repository: str,
        work_dir: str = None,
        username="Gato-X",
        email="gato-x@pwn.com",
        proxies=None,
        github_url="github.com",
    ):
        self.pat = pat
        self.repository = repository
        self.work_dir = work_dir if work_dir else tempfile.mkdtemp()
        if not github_url:
            self.github_url = "github.com"
        else:
            self.github_url = github_url

        if self.github_url != "github.com" or proxies:
            os.environ["GIT_SSL_NO_VERIFY"] = "True"

        if proxies:
            os.environ["ALL_PROXY"] = proxies["https"]

        self.clone_comamnd = (
            "git clone --depth 1 --filter=blob:none --sparse"
            f" https://{pat}@{self.github_url}/{repository}"
        )

        if len(repository.split("/")) != 2:
            raise ValueError("Repository name but be in Org/Repo format!")

        self.config_command1 = f"git config user.name '{username}'"
        self.config_command2 = f"git config user.email '{email}'"
        self.repository = repository

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    async def cleanup(self):
        """Clean up temporary directory"""
        if os.path.exists(self.work_dir):
            subprocess.run(["rm", "-rf", self.work_dir], check=True)

    async def get_non_default(self) -> list:
        """Get all workflows in non-default branches.

        Returns:
            list: List of Workflow objects
        """
        workflows = []
        try:
            url = f"https://{self.pat}@github.com/{self.repository}"

            # Create process to clone the repo
            proc = await asyncio.create_subprocess_exec(
                "git",
                "clone",
                "--no-checkout",
                url,
                self.work_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()

            # Get all remote branches
            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                self.work_dir,
                "branch",
                "-r",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            branches = stdout.decode().splitlines()
            for branch in branches:
                branch = branch.strip()
                if branch.startswith("origin/HEAD"):
                    continue

                # Checkout branch
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "-C",
                    self.work_dir,
                    "checkout",
                    branch.replace("origin/", ""),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()

                workflow_dir = os.path.join(self.work_dir, ".github", "workflows")
                if os.path.exists(workflow_dir):
                    for filename in os.listdir(workflow_dir):
                        if filename.endswith((".yml", ".yaml")):
                            with open(os.path.join(workflow_dir, filename), "r") as f:
                                contents = f.read()
                                workflows.append(
                                    Workflow(
                                        self.repository,
                                        contents,
                                        filename,
                                        default_branch=branch.replace("origin/", ""),
                                    )
                                )

        except subprocess.CalledProcessError as e:
            logger.warning(f"Git operation failed: {e}")
        except Exception as e:
            logger.warning(f"Error processing repository {self.repository}: {e}")
        finally:
            await self.cleanup()

        return workflows

    async def extract_workflow_ymls(self, repo_path: str = None):
        """Extracts and returns all github workflow .yml files located within
        the cloned repository.

        Args:
            repo_path (str, optional): Path on disk to repository to extract
            workflow yml files from. Defaults to repository associated with
            this object. Parameter intended for future uses and unit testing.
        Returns:
            list: List of yml files read from repository.
        """
        repo_path = repo_path if repo_path else self.work_dir
        ymls = []

        if os.path.isdir(os.path.join(repo_path, ".github", "workflows")):
            workflows = os.listdir(os.path.join(repo_path, ".github", "workflows"))
            for wf in workflows:
                wf_p = os.path.join(repo_path, ".github", "workflows", wf)
                if os.path.isfile(wf_p):
                    with open(wf_p, "r") as wf_in:
                        wf_yml = wf_in.read()
                        ymls.append((wf, wf_yml))
        return ymls
