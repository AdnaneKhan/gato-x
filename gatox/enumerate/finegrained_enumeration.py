import logging
from typing import Any

from gatox.cli.output import Output
from gatox.enumerate.enumerate import Enumerator
from gatox.github.api import Api
from gatox.models.repository import Repository

logger = logging.getLogger(__name__)


class FineGrainedEnumerator(Enumerator):
    """Class for enumerating fine-grained GitHub personal access tokens."""

    def __init__(
        self,
        pat: str = None,
        socks_proxy: str = None,
        http_proxy: str = None,
        skip_log: bool = False,
        github_url: str = None,
        output_json: str = None,
        ignore_workflow_run: bool = False,
        deep_dive: bool = False,
        app_permisions: list = None,
        api_client: Api = None,
    ):
        """Initialize the fine-grained enumerator.

        Inherits all functionality from the base Enumerator class and adds
        fine-grained token specific enumeration capabilities.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            http_proxy (str, optional): Proxy settings for HTTP proxy.
            skip_log (bool, optional): If set, then run logs will not be downloaded.
            github_url (str, optional): GitHub API URL.
            output_json (str, optional): JSON file to output enumeration results.
            ignore_workflow_run (bool, optional): If set, then "workflow_run" triggers will be ignored.
            deep_dive (bool, optional): If set, then deep dive workflow ingestion will be performed.
            app_permissions (list, optional): List of permissions for GitHub App.
            api_client (Api, optional): An existing Api client instance.
        """
        # Initialize the parent Enumerator class
        super().__init__(
            pat=pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            skip_log=skip_log,
            github_url=github_url,
            output_json=output_json,
            ignore_workflow_run=ignore_workflow_run,
            deep_dive=deep_dive,
            app_permisions=app_permisions,
            api_client=api_client,
        )

        # Fine-grained enumeration specific attributes
        self.accessible_repos = []

    async def __setup_user_info(self):
        """Sets up user/app token information."""
        if not self.user_perms:
            self.user_perms = await self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                f"The authenticated user is: {Output.bright(self.user_perms['user'])}"
            )

            if self.user_perms.get("expiration"):
                Output.info(
                    f"Token expiration: {Output.bright(self.user_perms['expiration'])}"
                )

        return True

    async def validate_token_and_get_user(self) -> bool:
        """Validates the token and gets the authenticated user.

        Uses the parent class's user setup functionality.

        Returns:
            bool: True if token is valid and user info retrieved, False otherwise.
        """
        # Use the parent class's setup method
        return await self.__setup_user_info()

    async def check_collaborator_access(self, repo: dict[str, Any]) -> bool:
        """Checks if the user has write+ access to a repository via collaborators endpoint.

        This endpoint only works if the user has write+ access to the repository.
        For fine-grained tokens, this indicates either:
        1. The token has access to all repos, OR
        2. The user explicitly opted this repo into the token's access

        Args:
            repo (Dict[str, Any]): Repository data from GitHub API.

        Returns:
            bool: True if user has write+ access, False otherwise.
        """
        try:
            result = await self.api.call_get(f"/repos/{repo}/collaborators")

            if result.status_code == 200:
                Output.tabbed(f"Write+ access to {Output.bright(f'{repo}')}")
                return True
            elif result.status_code == 403:
                # Expected for repos without write+ access
                return False
            else:
                Output.warn(f"Unexpected status {result.status_code} for {repo}")
                return False

        except Exception as e:
            logger.debug(
                f"Error checking collaborator access for {repo.get('full_name', 'unknown')}: {e}"
            )
            return False

    async def probe_write_access(
        self, repo_to_check: str, valid_scopes: set[str], is_public: bool = False
    ) -> None:
        """Probes write access to a repository by attempting to create a blob.

        Args:
            repo_to_check (str): Repository to probe for write access.
            valid_scopes (set[str]): Set of valid scopes to update if write access is found.
            is_public (bool): Whether the repository is public (allows probing without read permission).
        """
        if "contents:read" in valid_scopes or is_public:
            try:
                result = await self.api.call_post(
                    f"/repos/{repo_to_check}/git/blobs",
                    params={"content": "Write probe.", "encoding": "utf-8"},
                )
                if result.status_code == 201:
                    valid_scopes.discard(
                        "contents:read"
                    )  # Use discard to avoid KeyError
                    valid_scopes.add("contents:write")
            except Exception as e:
                Output.tabbed(f" contents:write: Error - {str(e)}")

    async def probe_pull_requests_write_access(
        self, repo_to_check: str, valid_scopes: set[str], is_public: bool = False
    ) -> None:
        """Probes pull requests write access by attempting to update a PR with no changes.

        Args:
            repo_to_check (str): Repository to probe for pull requests write access.
            valid_scopes (set[str]): Set of valid scopes to update if write access is found.
            is_public (bool): Whether the repository is public (allows probing without read permission).
        """
        if "pull_requests:read" in valid_scopes or is_public:
            try:
                # List pull requests
                prs_result = await self.api.call_get(f"/repos/{repo_to_check}/pulls")

                if prs_result.status_code == 200:
                    prs = prs_result.json()

                    # Find any open PR to test with
                    if prs:
                        pr_number = prs[0].get("number")

                        # Issue a PATCH request with no params to test write access
                        patch_result = await self.api.call_patch(
                            f"/repos/{repo_to_check}/pulls/{pr_number}", params={}
                        )

                        # 403 means not valid, other status codes indicate valid write access
                        if patch_result.status_code != 403:
                            valid_scopes.discard("pull_requests:read")
                            valid_scopes.add("pull_requests:write")

            except Exception as e:
                Output.tabbed(f" pull_requests:write: Error - {str(e)}")

    async def probe_actions_write_access(
        self, repo_to_check: str, valid_scopes: set[str], is_public: bool = False
    ) -> None:
        """Probes actions write access to a repository by attempting to get and then
        re-set the OIDC customization settings.

        Args:
            repo_to_check (str): Repository to probe for actions write access.
            valid_scopes (set[str]): Set of valid scopes to update if actions write access is found.
            is_public (bool): Whether the repository is public (allows probing without read permission).
        """
        if "actions:read" in valid_scopes or is_public:
            try:
                # Get current OIDC customization settings
                oidc_result = await self.api.call_get(
                    f"/repos/{repo_to_check}/actions/oidc/customization/sub"
                )

                if oidc_result.status_code == 200:
                    current_settings = oidc_result.json()

                    # Try to set the same settings back (should return 201/204 if we have write access)
                    set_result = await self.api.call_put(
                        f"/repos/{repo_to_check}/actions/oidc/customization/sub",
                        params=current_settings,
                    )

                    if set_result.status_code in [201, 204]:
                        valid_scopes.add("actions:write")
                        valid_scopes.discard("actions:read")

            except Exception as e:
                Output.tabbed(f" actions:write: Error - {str(e)}")

    async def probe_issue_write_access(
        self, repo_to_check: str, valid_scopes: set[str], is_public: bool = False
    ) -> None:
        """Probes issues write access by attempting to update an issue with no changes.

        Args:
            repo_to_check (str): Repository to probe for issues write access.
            valid_scopes (set[str]): Set of valid scopes to update if write access is found.
            is_public (bool): Whether the repository is public (allows probing without read permission).
        """
        if "issues:read" in valid_scopes or is_public:
            try:
                # List issues
                issues_result = await self.api.call_get(
                    f"/repos/{repo_to_check}/issues"
                )

                if issues_result.status_code == 200:
                    issues = issues_result.json()

                    # Find any issue to test with
                    if issues:
                        issue_number = issues[0].get("number")

                        # Issue a PATCH request with no params to test write access
                        patch_result = await self.api.call_patch(
                            f"/repos/{repo_to_check}/issues/{issue_number}", params={}
                        )

                        # 403 means not valid, other status codes indicate valid write access
                        if patch_result.status_code != 403:
                            valid_scopes.discard("issues:read")
                            valid_scopes.add("issues:write")

            except Exception as e:
                Output.tabbed(f" issues:write: Error - {str(e)}")

    async def detect_scopes(self, repo_to_check) -> set[str]:
        """Probes various GET endpoints to determine read scopes of the token.

        Args:
            has_private_repo_access (bool): Whether we have access to at least one private repo.

        Returns:
            Set[str]: Set of available scope names.
        """

        repo_data = await self.api.call_get(f"/repos/{repo_to_check}")
        if repo_data.json().get("private"):
            private_probes = True
        else:
            private_probes = False

        valid_scopes = set()

        # Full set of probes for tokens with private repo access
        private_probe_map = {
            "contents:read": f"/repos/{repo_to_check}/commits",  # Repository contents
            "issues:read": f"/repos/{repo_to_check}/issues",  # Issues
            "pull_requests:read": f"/repos/{repo_to_check}/pulls",  # Pull requests
            "actions:read": f"/repos/{repo_to_check}/actions/workflows",  # Actions
            "secrets:read": f"/repos/{repo_to_check}/actions/secrets",  # Secrets
            "administration:read": f"/repos/{repo_to_check}/actions/permissions",  # Administration
            "variables:read": f"/repos/{repo_to_check}/actions/variables",  # Variables
            "deployments:read": f"/repos/{repo_to_check}/deployments",  # Deployments
            "webhooks:read": f"/repos/{repo_to_check}/hooks",  # Webhooks
        }
        public_probe_map = {
            "administration:read": f"/repos/{repo_to_check}/actions/permissions",  # Administration
            "secrets:read": f"/repos/{repo_to_check}/actions/secrets",  # Secrets
            "variables:read": f"/repos/{repo_to_check}/actions/variables",  # Variables
        }

        if private_probes:
            probes = private_probe_map
        else:
            probes = public_probe_map

        Output.info("Probing endpoints to detect scopes...")

        for scope_name, endpoint in probes.items():
            try:
                result = await self.api.call_get(endpoint)
                has_permission = result.status_code == 200

                if has_permission:
                    valid_scopes.add(scope_name)

            except Exception as e:
                Output.tabbed(f" {scope_name}: Error - {str(e)}")

        is_public = not private_probes
        await self.probe_write_access(repo_to_check, valid_scopes, is_public)
        await self.probe_actions_write_access(repo_to_check, valid_scopes, is_public)
        await self.probe_pull_requests_write_access(
            repo_to_check, valid_scopes, is_public
        )
        await self.probe_issue_write_access(repo_to_check, valid_scopes, is_public)

        for scope in sorted(valid_scopes):
            Output.tabbed(f" {scope} ✅")

        return valid_scopes

    async def enumerate_fine_grained_token(
        self, enum_mode: str = "self", target_repo: str | None = None
    ) -> tuple[list[Repository], dict[str, Any]]:
        """Main enumeration method for fine-grained tokens.

        Args:
            enum_mode (str): Either "self" for self-enumeration or "single" for single repo.
            target_repo (Optional[str]): Target repository for single repo mode.

        Returns:
            Tuple[List[Repository], Dict[str, Any]]: Accessible repositories and enumeration results.
        """
        if enum_mode not in ["self", "single"]:
            raise ValueError("enum_mode must be either 'self' or 'single'")

        if enum_mode == "single" and not target_repo:
            raise ValueError("target_repo is required for single repo enumeration mode")

        Output.result("Starting fine-grained token enumeration")

        if not await self.validate_token_and_get_user():
            return [], {}

        public_repos = await self.api.get_own_repos(visibility="public")
        write_accessible_repos = []
        if public_repos:
            Output.info("Checking write+ access to public repositories...")
            for repo in public_repos:
                if await self.check_collaborator_access(repo):
                    write_accessible_repos.append(repo)
        else:
            Output.info("No public repositories found")

        private_repos = await self.api.get_own_repos(
            affiliation="owner,collaborator,organization_member", visibility="private"
        )
        has_private_access = len(private_repos) > 0

        if has_private_access:
            Output.info(f"Token has access to {len(private_repos)} private repo(s).")
            # Probe scopes on private repo - we just need to check one.
            # As the fg PAT model means it will be the same for all.
            self.app_permissions = await self.detect_scopes(private_repos[0])
        elif write_accessible_repos:
            Output.info("Token has public repository access only")
            self.app_permissions = await self.detect_scopes(write_accessible_repos[0])
        else:
            Output.info("Token has only public read access!")

        repositories = await self.enumerate_repos(
            write_accessible_repos + private_repos
        )

        # Prepare enumeration results
        enum_results = {
            "user": self.user_perms,
            "private_repos": len(private_repos),
            "write_accessible_repos": len(write_accessible_repos),
            "valid_scopes": self.app_permissions,
            "enum_mode": enum_mode,
        }

        return repositories, enum_results
