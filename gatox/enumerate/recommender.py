from gatox.cli.output import Output
from gatox.models.repository import Repository
from gatox.models.organization import Organization
from gatox.models.runner import Runner
from gatox.models.secret import Secret

from gatox.enumerate.reports.runners import RunnersReport


class Recommender:
    @staticmethod
    def print_repo_attack_recommendations(scopes: list, repository: Repository):
        """Prints attack recommendations for repositories.

        Args:
            scopes (list): List of scopes for user who ran Gato.
            repository (Repository): Repository wrapper object.
        """

        if not repository.sh_runner_access:
            if repository.is_admin():
                Output.owned(
                    "The user is an administrator on the repository, but no "
                    "self-hosted runners were detected!"
                )
            return

        if repository.is_admin():
            Output.owned("The user is an administrator on the repository!")
            if "workflow" in scopes:
                Output.result(
                    "The PAT also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The PAT does not have the workflow scope, which means an "
                    "existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )
                if repository.is_public():
                    Output.tabbed(
                        "Additionally, since the repository is public this "
                        "token can be used to approve a malicious fork PR!"
                    )
        elif repository.is_maintainer():
            Output.result("The user is a maintainer on the repository!")
            if "workflow" in scopes:
                Output.result(
                    "The user also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The user does not have the workflow scope, which means "
                    "an existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )
                if repository.is_public():
                    Output.tabbed(
                        "Additionally, since the repository is public this "
                        "token can be used to approve a malicious fork PR!"
                    )
        elif repository.can_push():
            Output.result("The user can push to the repository!")
            if "workflow" in scopes:
                Output.owned(
                    "The user also has the workflow scope, which means a "
                    "custom YAML payload can be used!"
                )
            else:
                Output.inform(
                    "The user does not have the workflow scope, which means "
                    "an existing workflow trigger must be used!"
                )
                Output.tabbed(
                    "Look for a job in the workflow YAML that checks out the "
                    "repository, AND then runs code that can be modified "
                    "within the repository!"
                )

    @staticmethod
    def print_repo_secrets(scopes, secrets: list[Secret]):
        """Prints list of repository level secrets.

        Args:
            scopes (list): List of OAuth scopes.
            secrets (list[Secret]): List of secret wrapper objects.
        """

        if not secrets:
            return

        if "workflow" in scopes:
            Output.owned(
                "The repository can access "
                f"{Output.bright(len(secrets))} secret(s) and the "
                "token can use a workflow to read them!"
            )
        else:
            Output.info(
                f"The repository can access "
                f"{Output.bright(len(secrets))} secret(s), but the "
                "token cannot trigger a new workflow!"
            )

        for secret in secrets:
            if secret.environment:
                Output.tabbed(
                    f"\t{Output.yellow('Environment')}: {Output.bright(secret.environment)},"
                    f" Secret Name: {Output.bright(secret.name)},"
                    f" last updated {Output.bright(secret.secret_data['updated_at'])}"
                )
            else:
                Output.tabbed(
                    f"\t{Output.bright(secret.name)},"
                    f" last updated {Output.bright(secret.secret_data['updated_at'])}"
                )

    @staticmethod
    def print_repo_runner_info(repository: Repository):
        """Prints information about repository level self-hosted runners.

        Args:
            repository (Repository): Repository wrapper object.
        """

        if repository.runners:
            Output.result(
                f"The repository has {len(repository.runners)} repo-level"
                " self-hosted runners!"
            )
            RunnersReport.report_runners(repository)

    @staticmethod
    def print_runner_info(runners: list[Runner]):
        """Print information about runners.

        Args:
            runners (dict): Runner result returned from the GitHub API
        """

        for runner in runners:
            runner_name = runner.runner_name
            runner_os = runner.os
            runner_status = runner.status
            labels = ", ".join([elem["name"] for elem in runner.labels])

            Output.tabbed(
                f"Name: {Output.bright(runner_name)}, OS: "
                f"{Output.bright(runner_os)} Status: "
                f"{Output.bright(runner_status)}"
            )

            if labels:
                Output.tabbed(f"The runner has the following labels: {labels}!")

    @staticmethod
    def print_org_findings(scopes, organization: Organization):
        """Prints findings related to an organization, and provides context for
        attacks/future investigation based on the scopes a user has.

        Args:
            organization (Organization): Organization wrapper object.
        """
        if organization.org_admin_user:
            Output.owned("The user is an organization owner!")
            if "admin:org" in scopes:
                Output.result(
                    f"The token also has the {Output.yellow('admin:org')} "
                    "scope. This token has extensive access to the GitHub"
                    " organization!"
                )
        elif organization.org_member:
            Output.result("The user is likely an organization member!")
        else:
            Output.warn("The user has only public access!")

        if organization.runners:
            Output.result(
                f"The organization has {len(organization.runners)} org-level"
                " self-hosted runners!"
            )
            Recommender.print_runner_info(organization.runners)

        if organization.secrets:
            Output.owned(
                f"The organization has "
                f"{Output.bright(len(organization.secrets))} secret(s)!"
            )
            Output.result("The secret names are:")
            for secret in organization.secrets:
                Output.tabbed(
                    f"\t{Output.bright(secret.name)}, "
                    f"last updated {secret.secret_data['updated_at']}"
                )
