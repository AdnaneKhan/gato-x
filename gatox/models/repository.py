import datetime

from gatox.enumerate.results.analysis_result import AnalysisResult
from gatox.models.runner import Runner
from gatox.models.secret import Secret


class Repository:
    """Simple wrapper class to provide accessor methods against the repository
    JSON response from GitHub.
    """

    def __init__(self, repo_data: dict):
        """Initialize wrapper class.

        Args:
            repo_json (dict): Dictionary from parsing JSON object returned from
            GitHub
        """
        self.repo_data = repo_data
        # Temporary hack until full transition to GQL
        if "environments" not in self.repo_data:
            self.repo_data["environments"] = []

        self.name = self.repo_data["full_name"]
        self.org_name = self.name.split("/")[0]
        self.secrets: list[Secret] = []
        self.org_secrets: list[Secret] = []
        self.sh_workflow_names = set()
        self.enum_time = datetime.datetime.now()

        self.permission_data = self.repo_data["permissions"]
        self.sh_runner_access = False
        self.accessible_runners: list[Runner] = []
        self.runners: list[Runner] = []
        self.risks = {}

    def is_admin(self):
        return self.permission_data.get("admin", False)

    def is_maintainer(self):
        return self.permission_data.get("maintain", False)

    def can_push(self):
        return self.permission_data.get("push", False)

    def can_pull(self):
        return self.permission_data.get("pull", False)

    def is_private(self):
        return self.repo_data["visibility"] != "public"

    def is_archived(self):
        return self.repo_data["archived"]

    def is_internal(self):
        return self.repo_data["visibility"] == "internal"

    def is_public(self):
        return self.repo_data["visibility"] == "public"

    def is_fork(self):
        return self.repo_data["fork"]

    def can_fork(self):
        return self.repo_data.get("allow_forking", False)

    def default_path(self):
        return f"{self.repo_data['html_url']}/blob/{self.repo_data['default_branch']}"

    def update_time(self):
        """Update timestamp."""
        self.enum_time = datetime.datetime.now()

    def set_accessible_org_secrets(self, secrets: list[Secret]):
        """Sets organization secrets that can be read using a workflow in
        this repository.

        Args:
            secrets (List[Secret]): List of Secret wrapper objects.
        """
        self.org_secrets = secrets

    def set_secrets(self, secrets: list[Secret]):
        """Sets secrets that are attached to this repository.

        Args:
            secrets (List[Secret]): List of repo level secret wrapper objects.
        """
        self.secrets = secrets

    def set_runners(self, runners: list[Runner]):
        """Sets list of self-hosted runners attached at the repository level."""
        self.sh_runner_access = True
        self.runners = runners

    def add_self_hosted_workflows(self, workflows: list):
        """Add a list of workflow file names that run on self-hosted runners."""
        self.sh_workflow_names.update(workflows)

    def get_sh_workflow_names(self):
        """Get names of workflows that might run on self-hosted runners."""
        return self.sh_workflow_names

    def add_accessible_runner(self, runner: Runner):
        """Add a runner is accessible by this repo. This runner could be org
        level or repo level.

        Args:
            runner (Runner): Runner wrapper object
        """
        self.sh_runner_access = True
        self.accessible_runners.append(runner)

    def get_risks(self):
        """Return repository risks."""
        return list(self.risks.values())

    def set_results(self, result: AnalysisResult):
        """Set results on the repository object."""
        key = result.get_first_and_last_hash()
        self.risks[key] = result

    def toJSON(self):
        """Converts the repository to a Gato JSON representation."""
        representation = {
            "name": self.name,
            "enum_time": self.enum_time.ctime(),
            "permissions": self.permission_data,
            "can_fork": self.can_fork(),
            "stars": self.repo_data["stargazers_count"],
            "runner_workflows": list(self.sh_workflow_names),
            "accessible_runners": [
                runner.toJSON() for runner in self.accessible_runners
            ],
            "repo_runners": [runner.toJSON() for runner in self.runners],
            "repo_secrets": [secret.toJSON() for secret in self.secrets],
            "org_secrets": [secret.toJSON() for secret in self.org_secrets],
            "risks": [risk.to_machine() for risk in self.get_risks()],
        }

        return representation
