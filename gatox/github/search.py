import time
import logging
import asyncio

from gatox.github.api import Api
from gatox.cli.output import Output
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


class Search:
    """Search utility for GH api in order to find public repos that may have
    security issues.
    """

    def __init__(self, api_accessor: Api):
        """Initialize class to call GH search methods.

        Args:
            api_accesor (Api): API accessor to use when making GitHub
            API requests.
        """
        self.api_accessor = api_accessor

    async def search_enumeration(
        self, organization: str = None, custom_query: str = None
    ):
        """Search for self-hosted in yml files within a given organization.

        Args:
            organization (str): Name of the github organization.
            custom_query (str, optional): Optional query to override default.

        Returns:
            set: Set containing repositories that are of interest.
        """

        query = {"sort": "indexed", "per_page": "100", "page": 1}

        if custom_query:
            query["q"] = custom_query
        else:
            query["q"] = (
                f"self-hosted org:{organization} language:yaml path:.github/workflows"
            )

        next_page = (
            f"/search/code?q={query['q']}&sort={query['sort']}"
            f"&per_page={query['per_page']}&page={query['page']}"
        )

        Output.info("Searching", end="", flush=True)
        candidates = set()
        while next_page:
            result = await self.api_accessor.call_get(next_page)
            print(".", end="", flush=True)
            code = result.status_code
            data = result.json()
            headers = result.headers

            if code == 403:
                retry_after = headers.get("retry-after")
                reset = headers.get("x-ratelimit-reset")
                sleep = 60
                if retry_after:
                    sleep = int(retry_after) + 5
                elif reset:
                    sleep = int(reset) - int(time.time()) + 5

                print()
                Output.warn(
                    f"Secondary API Rate Limit Hit. Sleeping for {sleep} seconds!"
                )
                await asyncio.sleep(sleep)

                Output.info("Searching", end="", flush=True)
                continue
            elif code != 200:
                print()
                Output.error(f"Search failed with response code {code}!")

                context = result.json()
                if "errors" in context and len(context["errors"]) > 0:
                    Output.warn(
                        "\tError message from GitHub:\n"
                        f"\t{context['errors'][0]['message']}"
                    )

                return candidates

            if "incomplete_results" in data and data["incomplete_results"]:
                print()
                Output.warn("Search results incomplete due to GitHub timeout!")

            for entry in data["items"]:
                candidates.add(entry["repository"]["full_name"])

            next_page = result.links.get("next", {}).get("url")
            if next_page:
                link = urlparse(next_page)
                next_page = f"{link.path}?{link.query}"
                await asyncio.sleep(5)

        print()
        return candidates
