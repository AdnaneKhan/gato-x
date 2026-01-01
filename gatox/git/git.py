import asyncio
import logging
import os
import subprocess
import tempfile

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
                    with open(wf_p) as wf_in:
                        wf_yml = wf_in.read()
                        ymls.append((wf, wf_yml))
        return ymls
