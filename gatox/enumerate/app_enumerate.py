import logging
from typing import List, Dict, Any

from gatox.github.api import Api
from gatox.models.repository import Repository
from gatox.github.app_auth import GitHubAppAuth
from gatox.cli.output import Output
from gatox.enumerate.enumerate import Enumerator
from gatox.models.execution import Execution

logger = logging.getLogger(__name__)


class AppEnumerator:
    """Handles GitHub App enumeration capabilities."""

    def __init__(
        self,
        app_id: str,
        private_key_path: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        github_url: str = "https://api.github.com",
        skip_log: bool = True,
        ignore_workflow_run: bool = False,
        deep_dive: bool = False,
    ):
        """Initialize App Enumerator.

        Args:
            app_id: GitHub App ID
            private_key_path: Path to private key PEM file
            socks_proxy: SOCKS proxy configuration
            http_proxy: HTTP proxy configuration
            github_url: GitHub API URL
            skip_log: Skip runner log analysis
            ignore_workflow_run: Ignore workflow_run triggers
            deep_dive: Perform deep dive analysis
        """
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.github_url = github_url
        self.skip_log = skip_log
        self.ignore_workflow_run = ignore_workflow_run
        self.deep_dive = deep_dive

        # Initialize App authentication
        self.app_auth = GitHubAppAuth(app_id, private_key_path)

        # This will be set when we generate the JWT
        self.api = None
        self.__app_permissions = None

    async def _initialize_api_with_jwt(self):
        """Initialize API with JWT token."""
        jwt_token = self.app_auth.generate_jwt()
        self.api = Api(
            jwt_token,
            socks_proxy=self.socks_proxy,
            http_proxy=self.http_proxy,
            github_url=self.github_url,
        )

    async def validate_app(self) -> Dict[str, Any]:
        """Validate the GitHub App and return basic information."""
        if not self.api:
            await self._initialize_api_with_jwt()

        app_info = await self.api.get_app_info()
        if not app_info:
            raise ValueError(
                "Failed to validate GitHub App - check App ID and private key"
            )

        self.__app_permissions = [
            f"{k}:{v}" for k, v in app_info["permissions"].items()
        ]

        Output.info(f"Successfully authenticated as GitHub App: {app_info['name']}")
        Output.info(f"App ID: {app_info['id']}")
        Output.info(f"Owner: {app_info['owner']['login']}")
        Output.info(f"Permissions: {Output.yellow(', '.join(self.__app_permissions))}")

        return app_info

    def report_installations(self, installations: List[Dict[str, Any]]):
        """Report the installations found."""
        if installations:
            for installation in installations:
                Output.info(f"Installation ID: {Output.yellow(installation['id'])}")
                Output.tabbed(
                    f"Account/Org: {Output.bright(installation['account']['login'])}"
                )
                if "repositories" in installation:
                    Output.tabbed(f"Repositories: {len(installation['repositories'])}")
                    for repo in installation["repositories"][:5]:  # Show first 5
                        Output.tabbed(f"  - {repo['full_name']}")
                    if len(installation["repositories"]) > 5:
                        Output.tabbed(
                            f"  ... and {len(installation['repositories']) - 5} more"
                        )
        else:
            Output.warn("No installations found")

    async def list_installations(self) -> List[Dict[str, Any]]:
        """List all installations for the GitHub App."""
        if not self.api:
            await self._initialize_api_with_jwt()

        installations = await self.api.get_app_installations()
        if not installations:
            Output.error("No installations found or failed to retrieve installations")
            return []

        Output.info(f"Found {len(installations)} installation(s)")

        enhanced_installations = []
        for installation in installations:
            # Get detailed installation info
            install_info = await self.api.get_installation_info(installation["id"])
            if install_info:
                # Get repositories for this installation
                repos_info = await self.api.get_installation_repositories(
                    installation["id"]
                )
                install_info["accessible_repositories"] = repos_info
                enhanced_installations.append(install_info)
            else:
                enhanced_installations.append(installation)

        return enhanced_installations

    async def enumerate_installation(self, installation_id: str) -> List[Repository]:
        """Enumerate a specific installation."""
        if not self.api:
            await self._initialize_api_with_jwt()

        if (
            "contents:read" not in self.__app_permissions
            and "contents:write" not in self.__app_permissions
        ):
            Output.error(
                "App does not have contents permissions, cannot enumerate repositories"
            )
            return []

        Output.info(f"Enumerating installation {installation_id}")

        # Get installation access token
        access_token_response = await self.api.get_installation_access_token(
            installation_id
        )
        if not access_token_response:
            Output.error(
                f"Failed to get access token for installation {installation_id}"
            )
            return None

        # Create new API instance with installation token
        installation_token = access_token_response["token"]
        installation_api = Api(
            installation_token,
            socks_proxy=self.socks_proxy,
            http_proxy=self.http_proxy,
            github_url=self.github_url,
        )

        # Get installation repositories
        installation_repos = await installation_api.get_installation_repos()
        if not installation_repos:
            Output.error(f"No repositories found for installation {installation_id}")
            return None

        Output.info(
            f"Found {installation_repos['total_count']} repositories in installation"
        )

        # Create standard enumerator with installation token
        enumerator = Enumerator(
            socks_proxy=self.socks_proxy,
            http_proxy=self.http_proxy,
            skip_log=self.skip_log,
            github_url=self.github_url,
            ignore_workflow_run=self.ignore_workflow_run,
            deep_dive=self.deep_dive,
            app_permisions=self.__app_permissions,
            api_client=installation_api,
        )

        # Enumerate repositories
        repos_to_enumerate = [
            repo["full_name"] for repo in installation_repos["repositories"]
        ]
        enumerated_repos = await enumerator.enumerate_repos(repos_to_enumerate)

        await installation_api.close()

        return enumerated_repos

    async def enumerate_all_installations(self) -> List[Execution]:
        """Enumerate all installations accessible to the GitHub App."""
        installations = await self.list_installations()

        results = []
        for installation in installations:
            installation_id = installation["id"]
            Output.info(
                f"Enumerating installation {installation_id} ({installation.get('account', {}).get('login', 'Unknown')})"
            )

            try:
                result = await self.enumerate_installation(str(installation_id))
                if result:
                    results.append(result)
            except Exception as e:
                Output.error(
                    f"Failed to enumerate installation {installation_id}: {str(e)}"
                )
                continue

        return results

    async def close(self):
        """Close API connections."""
        if self.api:
            await self.api.close()
