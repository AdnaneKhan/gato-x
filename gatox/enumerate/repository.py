import logging

from gatox.enumerate.reports.runners import RunnersReport
from gatox.cli.output import Output
from gatox.enumerate.reports.actions import ActionsReport
from gatox.models.execution import Repository
from gatox.models.secret import Secret
from gatox.models.runner import Runner
from gatox.github.api import Api

logger = logging.getLogger(__name__)


class RepositoryEnum:
    """Repository specific enumeration functionality."""

    def __init__(self, api: Api, skip_log: bool):
        """Initialize enumeration class with instantiated API wrapper and CLI
        parameters.

        Args:
            api (Api): GitHub API wraper object.
        """
        self.api = api
        self.skip_log = skip_log

    async def perform_runlog_enumeration(self, repository: Repository, workflows: list):
        """Enumerate for the presence of a self-hosted runner based on
        downloading historical runlogs.

        Args:
            repository (Repository): Wrapped repository object.
            workflows (list): List of workflows that execute on self-hosted runner.

        Returns:
            bool: True if a self-hosted runner was detected.
        """
        runner_detected = False
        wf_runs = []

        wf_runs = await self.api.retrieve_run_logs(repository.name, workflows=workflows)

        if wf_runs:
            for wf_run in wf_runs:
                runner = Runner(
                    wf_run["runner_name"],
                    wf_run["runner_type"],
                    wf_run["token_permissions"],
                    runner_group=wf_run["runner_group"],
                    machine_name=wf_run["machine_name"],
                    labels=wf_run["requested_labels"],
                    non_ephemeral=wf_run["non_ephemeral"],
                )

                repository.add_accessible_runner(runner)
            runner_detected = True

        return runner_detected

    async def enumerate_repository(self, repository: Repository):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if not repository.can_pull():
            Output.error("The user cannot pull, skipping.")
            return
        Output.tabbed(f"Checking repository: {Output.bright(repository.name)}")

        repository.update_time()
        if repository.get_risks():
            for risk in repository.get_risks():
                ActionsReport.report_actions_risk(risk)

        if repository.is_admin():
            runners = await self.api.get_repo_runners(repository.name)

            if runners:
                repo_runners = [
                    Runner(
                        runner["name"],
                        machine_name="N/A",
                        os=runner["os"],
                        status=runner["status"],
                        labels=[label["name"] for label in runner["labels"]],
                        runner_type="Repository",
                        runner_group="N/A",
                    )
                    for runner in runners
                ]

                repository.set_runners(repo_runners)
        else:
            runner_wfs = repository.get_sh_workflow_names()
            if runner_wfs:
                Output.info(f"Analyizing run logs for {repository.name}")
                runner_detected = await self.perform_runlog_enumeration(
                    repository, runner_wfs
                )
                if runner_detected:
                    RunnersReport.report_runners(repository)

    async def enumerate_repository_secrets(self, repository: Repository):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if repository.can_push():
            secrets = await self.api.get_secrets(repository.name)
            wrapped_env_secrets = []
            for environment in repository.repo_data["environments"]:
                env_secrets = await self.api.get_environment_secrets(
                    repository.name, environment
                )
                for secret in env_secrets:
                    wrapped_env_secrets.append(
                        Secret(secret, repository.name, environment)
                    )

            repo_secrets = [Secret(secret, repository.name) for secret in secrets]

            repo_secrets.extend(wrapped_env_secrets)
            repository.set_secrets(repo_secrets)

            org_secrets = await self.api.get_repo_org_secrets(repository.name)
            org_secrets = [
                Secret(secret, repository.org_name) for secret in org_secrets
            ]

            if org_secrets:
                repository.set_accessible_org_secrets(org_secrets)
