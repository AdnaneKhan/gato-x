from typing import List

from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.models.secret import Secret
from gatox.models.runner import Runner
from gatox.github.api import Api


class OrganizationEnum:
    """Helper class to wrap organization specific enumeration funcionality."""

    def __init__(self, api: Api):
        """Simple init method.

        Args:
            api (Api): Insantiated GitHub API wrapper object.
        """
        self.api = api

    async def __assemble_repo_list(
        self, organization: str, visibilities: list
    ) -> List[Repository]:
        """Get a list of repositories that match the visibility types.

        Args:
            organization (str): Name of the organization.
            visibilities (list): List of visibilities (public, private, etc)
        """

        repos = []
        for visibility in visibilities:
            raw_repos = await self.api.check_org_repos(organization, visibility)
            if raw_repos:
                repos.extend([Repository(repo) for repo in raw_repos])

        return repos

    async def construct_repo_enum_list(
        self, organization: Organization
    ) -> List[Repository]:
        """Constructs a list of repositories that a user has access to within
        an organization.

        Args:
            organization (Organization): Organization wrapper object.

        Returns:
            List[Repository]: List of repositories to enumerate.
        """
        org_private_repos = await self.__assemble_repo_list(
            organization.name, ["private", "internal"]
        )

        # We might legitimately have no private repos despite being a
        # member.
        if org_private_repos:
            sso_enabled = await self.api.validate_sso(
                organization.name, org_private_repos[0].name
            )
            organization.sso_enabled = sso_enabled
        else:
            org_private_repos = []

        org_public_repos = await self.__assemble_repo_list(
            organization.name, ["public"]
        )

        if organization.sso_enabled:
            return org_private_repos + org_public_repos
        else:
            return org_public_repos

    async def admin_enum(self, organization: Organization):
        """Enumeration tasks to perform if the user is an org admin and the
        token has the necessary scopes.
        """
        if organization.org_admin_scopes and organization.org_admin_user:
            runners = await self.api.check_org_runners(organization.name)
            if runners:
                org_runners = [
                    Runner(
                        runner["name"],
                        machine_name=None,
                        os=runner["os"],
                        status=runner["status"],
                        labels=runner["labels"],
                    )
                    for runner in runners["runners"]
                ]
                organization.set_runners(org_runners)

            org_secrets = await self.api.get_org_secrets(organization.name)
            if org_secrets:
                org_secrets = [
                    Secret(secret, organization.name) for secret in org_secrets
                ]

                organization.set_secrets(org_secrets)
