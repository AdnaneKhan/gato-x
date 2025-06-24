import logging
import httpx
import json
from typing import Optional, Set

from gatox.cli.output import Output
from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.github.search import Search
from gatox.github.api import Api


logger = logging.getLogger(__name__)


class Searcher:
    """Class that encapsulates functionality to use the GitHub code search API."""

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        github_url: str = None,
    ):
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        if self.api.transport:
            self.transport = self.api.transport
        else:
            self.transport = None

        self.user_perms = None

    async def __setup_user_info(self):
        """Checks the PAT to ensure that it is valid and retrieves the
        associated scopes.

        Returns:
            bool: If the PAT is associated with a valid user.
        """
        if not self.user_perms:
            self.user_perms = await self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                f"The authenticated user is: {Output.bright(self.user_perms['user'])}"
            )
            if len(self.user_perms["scopes"]) > 0:
                Output.info(
                    f"The GitHub Classic PAT has the following scopes: "
                    f"{Output.yellow(', '.join(self.user_perms['scopes']))}"
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    async def use_sourcegraph_api(
        self, organization: str, query=None, output_text=None
    ) -> Optional[Set[str]]:
        """Use SourceGraph's streaming search API to find repositories.

        Args:
            organization (str): Organization to search within
            query (str, optional): Custom search query. Defaults to None.
            output_text (str, optional): Output file for results. Defaults to None.

        Returns:
            Set[str]: Set of repository names found
        """
        repo_filter = f"repo:{organization}/ " if organization else ""
        url = "https://sourcegraph.com/.api/search/stream"
        headers = {"Content-Type": "application/json"}
        params = {
            "q": (
                "context:global "
                "self-hosted OR "
                "(runs-on AND NOT "
                f"/({'|'.join(ConfigurationManager().WORKFLOW_PARSING['GITHUB_HOSTED_LABELS'])})/) "
                f"{repo_filter}"
                "lang:YAML file:.github/workflows/ count:100000"
            )
        }

        if query:
            Output.info(
                f"Searching SourceGraph with the following query: {Output.bright(query)}"
            )
            params["q"] = query
        else:
            Output.info(
                f"Searching SourceGraph with the default Gato query: {Output.bright(params['q'])}"
            )

        results = set()
        try:
            async with httpx.AsyncClient(proxy=self.transport, http2=True) as client:
                async with client.stream(
                    "GET", url, headers=headers, params=params, timeout=60.0
                ) as response:
                    async for line in response.aiter_lines():
                        if line and line.startswith("data:"):
                            json_line = line.replace("data:", "").strip()
                            event = json.loads(json_line)

                            if (
                                "title" in event
                                and event["title"] == "Unable To Process Query"
                            ):
                                Output.error(
                                    "SourceGraph was unable to process the query!"
                                )
                                Output.error(
                                    f"Error: {Output.bright(event['description'])}"
                                )
                                return False

                            for element in event:
                                if "repository" in element:
                                    results.add(
                                        element["repository"].replace("github.com/", "")
                                    )
        except httpx.ReadTimeout as e:
            Output.warn(f"Request timed out: {str(e)}")
            pass

        return sorted(results)

    async def use_search_api(self, organization: str, query=None) -> Optional[Set[str]]:
        """Use GitHub's code search API to try and identify repositories
        using self-hosted runners.

        Args:
            organization (str): Organization to enumerate using
            the GitHub code search API.
            query (str, optional): Custom code-search query.

        Returns:
            Set[str]: Set of repositories found
        """
        await self.__setup_user_info()

        if not self.user_perms:
            return False

        api_search = Search(self.api)

        if query:
            Output.info(
                f"Searching GitHub with the following query: {Output.bright(query)}"
            )
        else:
            Output.info(
                f"Searching repositories within {Output.bright(organization)} "
                "using the GitHub Code Search API for 'self-hosted' within "
                "YAML files."
            )
        candidates = await api_search.search_enumeration(
            organization, custom_query=query
        )

        return sorted(candidates)

    def present_results(self, results, output_text=None):
        """Present search results and optionally write to file.

        Args:
            results (Set[str]): Set of repository names
            output_text (str, optional): Output file path. Defaults to None.
        """
        Output.result(
            f"Identified {len(results)} non-fork repositories that matched "
            "the criteria!"
        )

        if output_text:
            with open(output_text, "w") as file_output:
                for candidate in results:
                    file_output.write(f"{candidate}\n")

        for candidate in results:
            Output.tabbed(candidate)
