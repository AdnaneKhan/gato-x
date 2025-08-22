import asyncio
import logging

from gatox.caching.cache_manager import CacheManager
from gatox.cli.output import Output
from gatox.enumerate.deep_dive.ingest_non_default import IngestNonDefault
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.enumerate.organization import OrganizationEnum
from gatox.enumerate.recommender import Recommender
from gatox.enumerate.repository import RepositoryEnum
from gatox.github.api import Api
from gatox.github.gql_queries import GqlQueries
from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.visitors.artifact_poisoning_visitor import (
    ArtifactPoisoningVisitor,
)
from gatox.workflow_graph.visitors.dispatch_toctou_visitor import DispatchTOCTOUVisitor
from gatox.workflow_graph.visitors.injection_visitor import InjectionVisitor
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.visitors.review_injection_visitor import (
    ReviewInjectionVisitor,
)
from gatox.workflow_graph.visitors.runner_visitor import RunnerVisitor
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils

logger = logging.getLogger(__name__)


class Enumerator:
    """Class holding all high level logic for enumerating GitHub."""

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
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            Defaults to None.
            http_proxy (str, optional): Proxy gettings for HTTP proxy.
            Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be
            downloaded.
            output_json (str, optional): JSON file to output enumeration
            results.
            ignore_workflow_run (bool, optional): If set, then
            "workflow_run" triggers will be ignored.
            deep_dive (bool, optional): If set, then deep dive workflow
            ingestion will be performed. This will slow down enumeration
            significantly, but will provide more information about workflows
            and their runs.
            app_permissions (list, optional): List of permissions for GitHub App.
            api_client (Api, optional): An existing Api client instance.
            Defaults to None.
        """
        if api_client:
            self.api = api_client
        else:
            if not pat:
                raise ValueError("A valid GitHub token must be provided!")
            self.api = Api(
                pat,
                socks_proxy=socks_proxy,
                http_proxy=http_proxy,
                github_url=github_url,
            )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.user_perms = None
        self.github_url = github_url
        self.output_json = output_json
        self.deep_dive = deep_dive
        self.ignore_workflow_run = ignore_workflow_run
        self.app_permissions = app_permisions

        self.repo_e = RepositoryEnum(self.api, skip_log)
        self.org_e = OrganizationEnum(self.api)

    async def __setup_user_info(self):
        """Sets up user/app token information."""
        if not self.user_perms and self.api.is_app_token():
            installation_info = await self.api.get_installation_repos()

            if installation_info:
                count = installation_info["total_count"]
                if count > 0:
                    self.user_perms = {
                        "user": "Github App",
                        "scopes": self.app_permissions or [],
                        "name": "GATO-X App Mode",
                    }

                    return True
                else:
                    return False

        if not self.user_perms:
            self.user_perms = await self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                f"The authenticated user is: {Output.bright(self.user_perms['user'])}"
            )
            if len(self.user_perms["scopes"]):
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f"{Output.yellow(', '.join(self.user_perms['scopes']))}"
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    async def __query_graphql_workflows(self, queries):
        """
        Query workflows using the GitHub GraphQL API.

        This method performs an IO-heavy operation by querying workflows in batches.
        It utilizes a semaphore to limit concurrent execution to 4 workers.

        Args:
            queries (List[Any]): A list of GraphQL query objects to be executed.

        Returns:
            None

        Raises:
            Exception: Propagates any exceptions raised during the query execution.
        """
        Output.info(f"Querying repositories in {len(queries)} batches!")
        semaphore = asyncio.Semaphore(4)
        tasks = []

        async def bounded_query(query, i):
            async with semaphore:
                return await DataIngestor.perform_query(self.api, query, i)

        for i, wf_query in enumerate(queries):
            tasks.append(bounded_query(wf_query, i))

        for coro in asyncio.as_completed(tasks):
            result = await coro
            Output.info(
                f"Processed {DataIngestor.check_status()}/{len(queries)} batches.",
                end="\r",
            )
            await DataIngestor.construct_workflow_cache(result)

    async def __retrieve_missing_ymls(self, repo_name: str):
        """ """
        repo = CacheManager().is_repo_cached(repo_name)
        if not repo:
            repo_data = await self.api.get_repository(repo_name)
            if repo_data:
                repo = Repository(repo_data)
                CacheManager().set_repository(repo)

                if repo:
                    workflows = await self.api.retrieve_workflow_ymls(repo.name)

                    for workflow in workflows:
                        CacheManager().set_workflow(
                            repo.name, workflow.workflow_name, workflow
                        )
            else:
                Output.warn(
                    f"Unable to retrieve workflows for {Output.bright(repo_name)}! "
                    "Ensure the repository exists and the user has access."
                )

    async def enumerate_repo(self, repo_name: str) -> Repository:
        """Enumerate only a single repository. No checks for org-level
        self-hosted runners will be performed in this case.

        Args:
            repo_name (str): Repository name in {Org/Owner}/Repo format.
            large_enum (bool, optional): Whether to only download
            run logs when workflow analysis detects runners. Defaults to False.
        """
        if not await self.__setup_user_info():
            return False

        repo = CacheManager().get_repository(repo_name)

        if not repo:
            repo_data = await self.api.get_repository(repo_name)
            if repo_data:
                repo = Repository(repo_data)
                CacheManager().set_repository(repo)

        if repo:
            if repo.is_archived():
                Output.tabbed(
                    f"Skipping archived repository: {Output.bright(repo.name)}!"
                )
                return False

            await self.repo_e.enumerate_repository(repo)
            await self.repo_e.enumerate_repository_secrets(repo)
            Recommender.print_repo_secrets(
                self.user_perms["scopes"], repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms["scopes"], repo
            )

            return repo
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                "exist or the user does not have access."
            )

    async def enumerate_commit(self, repo_name: str, sha: str):
        """Enumerate a single commit of a repository.

        Workflow files from the commit are treated as if they are on the
        repository's default branch so that default-branch checks apply.

        Args:
            repo_name (str): Repository in Org/Repo format.
            sha (str): Commit SHA to analyze.

        Returns:
            Repository | bool: Repository wrapper populated with results or
            False on failure.
        """
        if not await self.__setup_user_info():
            return False

        repo_data = await self.api.get_repository(repo_name)
        if not repo_data:
            Output.warn(f"Unable to retrieve repository: {Output.bright(repo_name)}")
            return False

        repo = Repository(repo_data)
        CacheManager().set_repository(repo)

        workflows = await self.api.retrieve_workflow_ymls_ref(repo.name, sha)
        for workflow in workflows:
            # Override the branch to the default to "trick" graph into
            # thinking commit is merged to default.
            workflow.branch = repo.repo_data["default_branch"]
            CacheManager().set_workflow(repo.name, workflow.workflow_name, workflow)
            await WorkflowGraphBuilder().build_graph_from_yaml(workflow, repo)

        await self.process_graph()
        await self.repo_e.enumerate_repository(repo)

        return repo

    async def __finalize_caches(self, repos: list):
        """Finalizes the caches for the repositories enumerated.

        Args:
            repos (list): List of Repository objects.
        """
        semaphore = asyncio.Semaphore(25)

        async def sem_retrieve(repo):
            async with semaphore:
                await self.__retrieve_missing_ymls(repo.name)

        tasks = [asyncio.create_task(sem_retrieve(repo)) for repo in repos]
        await asyncio.gather(*tasks)

    async def validate_only(self) -> Organization:
        """Validates the PAT access and exits."""
        if not await self.__setup_user_info():
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = await self.api.check_organizations()

        Output.info(
            f"The user {self.user_perms['user']} belongs to {len(orgs)} organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [
            Organization({"login": org}, self.user_perms["scopes"], True)
            for org in orgs
        ]

    async def self_enumeration(self) -> tuple[list[Organization], list[Repository]]:
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            bool: False if the PAT is not valid for enumeration.
            (list, list): Tuple containing list of orgs and list of repos.
        """
        await self.__setup_user_info()

        if not self.user_perms:
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        Output.info("Enumerating user owned repositories!")

        repos = await self.api.get_own_repos()
        repo_wrappers = await self.enumerate_repos(repos)
        orgs = await self.api.check_organizations()

        Output.info(
            f"The user {self.user_perms['user']} belongs to {len(orgs)} organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = []
        for org in orgs:
            wrapper = await self.enumerate_organization(org)
            org_wrappers.append(wrapper)
            # Clear the graph after each organization to avoid
            # excessive node visits.
            WorkflowGraphBuilder().graph.clear()

        return org_wrappers, repo_wrappers

    async def enumerate_user(self, user: str):
        """Enumerate a user's repositories."""

        if not await self.__setup_user_info():
            return False

        repos = await self.api.get_user_repos(user)

        if not repos:
            Output.warn(
                f"Unable to query the user: {Output.bright(user)}! Ensure the "
                "user exists!"
            )
            return False

        Output.result(f"Enumerating the {Output.bright(user)} user!")

        repo_wrappers = await self.enumerate_repos(repos)

        return repo_wrappers

    async def enumerate_organization(self, org: str) -> Organization:
        """Enumerate an entire organization, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            org (str): Organization to perform enumeration on.

        Returns:
            bool: False if a failure occurred enumerating the organization.
        """

        if not await self.__setup_user_info():
            return False

        details = await self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!"
            )
            return False

        organization = Organization(details, self.user_perms["scopes"])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            await self.org_e.admin_enum(organization)

        Recommender.print_org_findings(self.user_perms["scopes"], organization)

        Output.info("Querying repository list!")
        enum_list = await self.org_e.construct_repo_enum_list(organization)

        Output.info(
            f"About to enumerate "
            f"{len(enum_list)} "
            "non-archived repos within "
            f"the {organization.name} organization!"
        )

        Output.info("Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)
        await self.__query_graphql_workflows(wf_queries)
        await self.__finalize_caches(enum_list)

        if self.deep_dive:
            Output.inform(
                "Deep dive workflow ingestion enabled, this will slow down enumeration!"
            )
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if self.skip_log and repo.is_fork():
                    continue

                cached_repo = CacheManager().get_repository(repo.name)
                if self.deep_dive and not cached_repo.is_fork():
                    await IngestNonDefault.ingest(cached_repo, self.api)

            await IngestNonDefault.pool_empty()
            Output.info("Deep dive ingestion complete!")

        await self.process_graph()

        try:
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if repo.is_fork():
                    continue

                repo = CacheManager().get_repository(repo.name)
                if repo:
                    await self.repo_e.enumerate_repository(repo)
                    Recommender.print_repo_attack_recommendations(
                        self.user_perms["scopes"], repo
                    )
                    await self.repo_e.enumerate_repository_secrets(repo)
                    Recommender.print_repo_secrets(
                        self.user_perms["scopes"], repo.secrets + repo.org_secrets
                    )
                    Recommender.print_repo_runner_info(repo)
                    organization.set_repository(repo)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return organization

    async def process_graph(self):
        """Process the workflow graph using multiple visitors concurrently."""
        Output.info(
            f"Performing graph analysis on {WorkflowGraphBuilder().graph.number_of_nodes()} nodes!"
        )

        visitors = [
            (PwnRequestVisitor, "find_pwn_requests"),
            (InjectionVisitor, "find_injections"),
            (ReviewInjectionVisitor, "find_injections"),
            (DispatchTOCTOUVisitor, "find_dispatch_misconfigurations"),
            (ArtifactPoisoningVisitor, "find_artifact_poisoning"),
        ]

        # Create tasks for each visitor
        async def run_visitor(visitor_class, visitor_method):
            visitor = visitor_class()
            visitor_func = getattr(visitor, visitor_method)

            try:
                if visitor_class in (PwnRequestVisitor, InjectionVisitor):
                    return await visitor_func(
                        WorkflowGraphBuilder().graph, self.api, self.ignore_workflow_run
                    )
                else:
                    return await visitor_func(WorkflowGraphBuilder().graph, self.api)
            except Exception as e:
                logger.error(f"Error in {visitor_class.__name__}: {e}")
                return None

        # Run all visitors concurrently
        visitor_results = await asyncio.gather(
            *(run_visitor(v_class, v_method) for v_class, v_method in visitors),
            return_exceptions=True,
        )

        # Process results
        for visitor_class, results in zip(visitors, visitor_results, strict=False):
            if results and not isinstance(results, Exception):
                await VisitorUtils.add_repo_results(results, self.api)
            elif isinstance(results, Exception):
                logger.error(f"Error in {visitor_class[0].__name__}: {results}")

        if not self.skip_log:
            await RunnerVisitor.find_runner_workflows(WorkflowGraphBuilder().graph)

    async def enumerate_repos(self, repo_names: list) -> list[Repository]:
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): Repository name in {Org/Owner}/Repo format.
        """
        repo_wrappers = []
        if not await self.__setup_user_info():
            return repo_wrappers

        if len(repo_names) == 0:
            Output.error("The list of repositories was empty!")
            return repo_wrappers

        Output.info(
            f"Querying and caching workflow YAML files "
            f"from {len(repo_names)} repositories!"
        )
        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)
        await self.__query_graphql_workflows(queries)
        for repo in repo_names:
            await self.__retrieve_missing_ymls(repo)

        if self.deep_dive:
            Output.inform(
                "Performing deep dive workflow ingestion, this will be a very slow process!"
            )
            for repo in repo_names:
                repo_obj = CacheManager().get_repository(repo)
                await IngestNonDefault.ingest(repo_obj, self.api)

        await IngestNonDefault.pool_empty()
        await self.process_graph()

        try:
            for repo in repo_names:
                repo_obj = await self.enumerate_repo(repo)
                if repo_obj:
                    repo_wrappers.append(repo_obj)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return repo_wrappers
