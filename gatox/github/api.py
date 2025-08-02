import base64
import copy
import httpx
import logging
import zipfile
import re
import io
import asyncio

from gatox.cli.output import Output
from datetime import datetime, timezone, timedelta
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.models.workflow import Workflow
from gatox.github.gql_queries import GqlQueries

logger = logging.getLogger(__name__)


class Api:
    """Class to serve as an abstraction layer to interact with the GitHub API.
    It handles utilizing proxies, along with passing the PAT and handling any
    rate limiting or network issues.
    """

    RUNNER_RE = re.compile(r"Runner name: \'([\w+-.]+)\'")
    MACHINE_RE = re.compile(r"Machine name: \'([\w+-.]+)\'")
    RUNNERGROUP_RE = re.compile(r"Runner group name: \'([\w+-.]+)\'")
    RUNNERTYPE_RE = re.compile(r"([\w+-.]+)")

    RUN_THRESHOLD = 90

    def __init__(
        self,
        pat: str,
        version: str = "2022-11-28",
        http_proxy: str = None,
        socks_proxy: str = None,
        github_url: str = "https://api.github.com",
        client: httpx.AsyncClient = None,  # Optional, mostly for unit tests.
        app_permissions: list = None,  # Optional, for GitHub App tokens
    ):
        """Initialize the API abstraction layer to interact with the GitHub
        REST API.

        Args:
            pat (str): GitHub personal access token that will be used for API
            calls.
            version (str): API version to use that will be passed with the
            X-GitHub-Api-Version header.
            http_proxy (str, optional): HTTP Proxy to use for API calls.
            Defaults to None.
            socks_proxy (str, optional): SOCKS Proxy to use for API calls.
            Defaults to None.
        """
        self.pat = pat
        self.transport = None
        self.verify_ssl = True
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {pat}",
            "X-GitHub-Api-Version": version,
        }
        if not github_url:
            self.github_url = "https://api.github.com"
        else:
            self.github_url = github_url

        if http_proxy and socks_proxy:
            raise ValueError(
                "A SOCKS & HTTP proxy cannot be used at the same "
                "time! Please pass only one!"
            )

        if http_proxy:
            # We are likely using BURP, so disable SSL.
            self.verify_ssl = False
            self.transport = f"http://{http_proxy}"
        elif socks_proxy:
            self.transport = f"socks5://{socks_proxy}"

        if self.github_url != "https://api.github.com":
            self.verify_ssl = False

        # Initialize async client
        if client:
            self.client = client
        else:
            self.client = httpx.AsyncClient(
                headers=self.headers,
                http2=True,
                proxy=self.transport,
                verify=self.verify_ssl,
                follow_redirects=True,
                timeout=30.0,
            )
        self.app_permissions = app_permissions

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the async client"""
        await self.client.aclose()

    async def __check_rate_limit(self, headers):
        """Checks the rate limit, and pauses Gato execution until the rate
        limit resets.
        """
        if (
            "X-Ratelimit-Remaining" in headers
            and int(headers["X-Ratelimit-Remaining"])
            < int(headers["X-RateLimit-Limit"]) // 20
            and headers["X-Ratelimit-Resource"] == "core"
        ):
            gh_date = headers["Date"]
            reset_utc = int(headers["X-Ratelimit-Reset"])
            # Convert date to UTC
            date = datetime.strptime(gh_date, "%a, %d %b %Y %H:%M:%S %Z")
            date = date.replace(tzinfo=timezone.utc)
            reset_time = date.fromtimestamp(reset_utc, tz=timezone.utc)

            sleep_time = (reset_time - date).seconds
            sleep_time_mins = str(sleep_time // 60)

            # Yes, we are breaking the "don't print in API code" rule; however,
            # the alternative would be to handle a rate limit exception in
            # all calling code. We inform the here user that we are sleeping.
            # very large orgs will take several hours to enumerate, especially
            # if runlog enumeration is enabled.
            Output.warn(
                f"Sleeping for {Output.bright(sleep_time_mins + ' minutes')} "
                "to prevent rate limit exhaustion!"
            )

            await asyncio.sleep(sleep_time + 1)

    async def __process_run_log(self, log_content: bytes, run_info: dict):
        """Utility method to process a run log zip file.

        Args:
            log_content (bytes): Zip file downloaded from GitHub
            run_info (dict): Metadata about the run from the GitHub API
        Returns:
            dict: metadata about the run execution.
        """
        log_package = dict()
        token_permissions = dict()
        runner_type = None
        non_ephemeral = False
        labels = []
        runner_name = None
        machine_name = None
        runner_group = None

        with zipfile.ZipFile(io.BytesIO(log_content)) as runres:
            for zipinfo in runres.infolist():
                if re.match("[0-9]{1}_.*", zipinfo.filename):
                    with runres.open(zipinfo) as run_setup:
                        content = run_setup.read().decode()
                        content_lines = content.split("\n")
                        if (
                            "Image Release: https://github.com/actions/runner-images"
                            in content
                            or "Job is about to start running on the hosted runner: GitHub Actions"
                            in content
                        ) and "1ES.Pool" not in content:
                            # Larger runners will appear to be self-hosted, but
                            # they will have the image name. Skip if we see this.
                            # If the log contains "job is about to start running on hosted runner",
                            # the runner is a Github hosted runner so we can skip it.
                            continue
                        elif (
                            "Self-hosted runners in the repository are disabled"
                            in content
                        ):
                            break
                        index = 0
                        while index < len(content_lines) and content_lines[index]:
                            line = content_lines[index]

                            if "Requested labels: " in line:
                                labels = line.split("Requested labels: ")[1].split(", ")

                            if "Runner name: " in line:
                                runner_name = line.split("Runner name: ")[1].replace(
                                    "'", ""
                                )

                            if "Machine name: " in line:
                                machine_name = line.split("Machine name: ")[1].replace(
                                    "'", ""
                                )

                            if "Runner group name:" in line:
                                runner_group = line.split("Runner group name: ")[
                                    1
                                ].replace("'", "")

                            if "Job is about to start running on" in line:
                                runner_type = line.split()[-1]
                                matches = Api.RUNNERTYPE_RE.search(runner_type)
                                runner_type = matches.group(1)

                            if "GITHUB_TOKEN Permission" in line:
                                while "[endgroup]" not in content_lines[index + 1]:
                                    index += 1
                                    scope = (
                                        content_lines[index].split()[1].replace(":", "")
                                    )
                                    permission = content_lines[index].split()[2]
                                    token_permissions[scope] = permission
                                log_package["token_permissions"] = token_permissions

                            if "Cleaning the repository" in line:
                                non_ephemeral = True
                            log_package["non_ephemeral"] = non_ephemeral

                            index += 1

                        # Continue if there is no runner name. This means
                        # we picked up a pending workflow.
                        if not runner_name:
                            continue

                        log_package = {
                            "requested_labels": labels,
                            "runner_name": runner_name,
                            "machine_name": machine_name,
                            "runner_group": runner_group,
                            "runner_type": runner_type,
                            "run_id": run_info["id"],
                            "run_attempt": run_info["run_attempt"],
                            "non_ephemeral": non_ephemeral,
                            "token_permissions": token_permissions,
                        }

                    return log_package

    async def __get_full_runlog(self, log_content: bytes, run_name: str):
        """Gets the full text of the runlog from the zip file by matching the
         filename.

        Args:
            log_content (bytes): zip file binary
            run_name (str): Name of file to look for

        Returns:
            str: Runlog content
        """
        with zipfile.ZipFile(io.BytesIO(log_content)) as runres:
            for zipinfo in runres.infolist():
                if f"0_{run_name}" in zipinfo.filename:
                    with runres.open(zipinfo) as run_log:
                        content = run_log.read().decode()

                        return content

    async def __get_raw_file(self, repo: str, file_path: str, ref: str):
        """Get a raw file with a web request, retrying on RemoteProtocolError."""
        url = f"https://raw.githubusercontent.com/{repo}/{ref}/{file_path}"
        headers = {
            "Authorization": "None",
            "Accept": "text/plain",
        }
        attempt = 0
        while attempt < 3:
            try:
                resp = await self.client.get(url, headers=headers)
                break
            except httpx.RemoteProtocolError:
                attempt += 1
                await asyncio.sleep(1)
        else:
            # All attempts failed.
            return None

        if resp.status_code == 404:
            return None
        elif resp.status_code == 200:
            return resp.text

    @staticmethod
    def __verify_result(response: httpx.Response, expected_code: int):
        """Verifies that the response matches the expected code. If it does not
        match, then the response is logged and the program exits.

        Args:
            response (httpx.Response): Response object from a request.
            expected_code (int): Expected status code from the request.
        """
        if response.status_code != expected_code:
            logger.warning(
                f"Expected status code {expected_code}, but got {response.status_code}!"
            )
            logger.debug(response.text)
            return False
        return True

    def is_app_token(self):
        """Returns if the API is using a GitHub App installation token."""
        return self.pat.startswith("ghs_")

    async def call_get(self, url: str, params: dict = None, strip_auth=False):
        """Internal method to wrap a GET request so that proxies and headers
        do not need to be repeated.

        Args:
            url (str): Url path for the API request
            params (dict, optional): Parameters to pass to the request.
            strip_auth (bool): Whether to make the request without any auth
            token. Defaults to False.
            Defaults to None.

        Returns:
            Response: Returns the requests response object.
        """
        request_url = self.github_url + url

        get_header = copy.deepcopy(self.headers)
        if strip_auth:
            del get_header["Authorization"]

        api_response = None
        for _ in range(0, 5):
            try:
                logger.debug(f"Making GET API request to {request_url}!")

                api_response = await self.client.get(
                    request_url,
                    params=params,
                    headers=get_header,
                )

                break
            except Exception as e:
                logger.warning(
                    f"GET request {request_url} failed due to transport error re-trying",
                    exc_info=e,
                )
                continue

        if api_response is None:
            raise Exception(f"GET request {request_url} failed after 5 attempts")

        if not strip_auth:
            await self.__check_rate_limit(api_response.headers)

        return api_response

    async def call_post(self, url: str, params: dict = None):
        """Internal method to wrap a POST request so that proxies and headers
        do not need to be updated in each method.

        Args:
            url (str): URL path to make POST request to.
            params (dict, optional): Parameters to send as part of the request.
            Defaults to None.
        Returns:
            Response: Returns the requests response object.
        """
        request_url = self.github_url + url
        logger.debug(f"Making POST API request to {request_url}!")

        api_response = await self.client.post(request_url, json=params, timeout=30)
        logger.debug(
            f"The POST request to {request_url} returned a {api_response.status_code}!"
        )

        await self.__check_rate_limit(api_response.headers)

        return api_response

    async def call_patch(self, url: str, params: dict = None):
        """Internal method to wrap a PATCH request so that proxies and headers
        do not need to be updated in each method.

        Args:
            url (str): URL path to make PATCH request to.
            params (dict, optional): Parameters to send as part of the request.
            Defaults to None.
        Returns:
            Response: Returns the requests response object.
        """
        request_url = self.github_url + url
        logger.debug(f"Making PATCH API request to {request_url}!")

        api_response = await self.client.patch(request_url, json=params)
        logger.debug(
            f"The PATCH request to {request_url} returned a {api_response.status_code}!"
        )

        await self.__check_rate_limit(api_response.headers)

        return api_response

    async def call_put(self, url: str, params: dict = None):
        """Internal method to wrap a PUT request so that proxies and headers
        do not need to be updated in each method.

        Args:
            url (stre): _description_
            params (dict, optional): _description_. Defaults to None.
        """
        request_url = self.github_url + url
        logger.debug(f"Making PUT API request to {request_url}!")

        api_response = await self.client.put(request_url, json=params)

        await self.__check_rate_limit(api_response.headers)

        return api_response

    async def call_delete(self, url: str):
        """Internal method to wrap a POST request so that proxies and headers
        do not need to be updated in each method.

        Args:
            url (str): URL path to make POST request to.

        Returns:
            Response: Returns the requests response object.
        """
        request_url = self.github_url + url
        logger.debug(f"Making DELETE API request to {request_url}!")

        api_response = await self.client.delete(request_url)
        logger.debug(
            f"The POST request to {request_url} returned a {api_response.status_code}!"
        )

        await self.__check_rate_limit(api_response.headers)

        return api_response

    async def delete_repository(self, repo_name: str):
        """Deletes the provided repository, if the user has administrative
        permissions on that repository.

        Args:
            repo_name (str): Name of repository to delete in Org/Owner format.
        Returns:
            bool: True if the repository was deleted, False otherwise.
        """
        result = await self.call_delete(f"/repos/{repo_name}")

        if result.status_code == 204:
            logger.info(f"Successfully deleted {repo_name}!")
        else:
            logger.warning(f"Unable to delete repository {repo_name}!")
            return False

        return True

    async def fork_repository(self, repo_name: str):
        """Creates a fork of a public repository and returns the name of
        the newly created fork.

        Args:
            repo_name (str): Name of the repository to fork.

        Returns:
            str: Full name of the newly forked repo in User/Repo format. False
            if there was a faiure.
        """
        post_params = {"default_branch_only": True}

        result = await self.call_post(f"/repos/{repo_name}/forks", params=post_params)

        if result.status_code == 202:
            fork_info = result.json()
            return fork_info["full_name"]
        elif result.status_code == 403:
            # likely permission error, log it.
            logger.warning("Forking this repository is forbidden!")
            return False
        elif result.status_code == 404:
            logger.warning("Unable to fork due to 404, ensure repository exists.")
            return False
        else:
            logger.warning("Repository fork failed!")
            return False

    async def create_fork_pr(
        self,
        target_repo: str,
        source_user: str,
        source_branch: str,
        target_branch: str,
        pr_title: str,
    ):
        """Creates a pull request from source_repo to target_repo. This is

        Args:
            target_repo (str): Target repo  (the one we are targeting)
            source_repo (str): Source repo for the PR (the one we own)
        Returns:
            str: URL of the newly created pull-request.
        """
        pr_params = {
            "title": pr_title,
            "head": f"{source_user}:{source_branch}",
            "base": f"{target_branch}",
            "body": "This is a test pull request created for CI/CD"
            " vulnerability testing purposes.",
            "maintainer_can_modify": False,
            "draft": True,
        }

        result = await self.call_post(f"/repos/{target_repo}/pulls", params=pr_params)

        if result.status_code == 201:
            details = result.json()
            return details["html_url"]
        else:
            logger.warning(
                f"Failed to create PR for fork,"
                f" the status code was: {result.status_code}!"
            )
            return None

    async def check_organizations(self):
        """Check organizations that the authenticated user belongs to.

        Returns:
            list(str): List of strings containing the organization names that
            the user is a member of.
        """
        organizations = []
        page = 1
        per_page = 100

        while True:
            params = {"page": page, "per_page": per_page}
            result = await self.call_get("/user/orgs", params=params)

            if result.status_code == 200:
                orgs = result.json()
                if not orgs:
                    break

                organizations.extend([org["login"] for org in orgs])
                page += 1
            elif result.status_code == 403:
                break
            else:
                break

        return organizations

    async def get_repository(self, repository: str):
        """Retrieve a repository using the GitHub API.

        Args:
            repository (str): Repository name in org/Repo format.
        Returns:
            dict: Dictionary containing repository info from the GitHub API.
        """
        result = await self.call_get(f"/repos/{repository}")

        if result.status_code == 200:
            return result.json()

    async def get_user_type(self, username: str):
        """
        Retrieve the type of a user from the API.

        This function sends a GET request to the API to retrieve information about a user specified by the username.
        If the request is successful (status code 200), it returns the type of the user.

        Args:
            username (str): The username of the user whose type is to be retrieved.

        Returns:
            str: The type of the user if the request is successful.

        Raises:
            httpx.RequestError: If the request fails due to network issues or invalid responses.
            KeyError: If the 'type' key is not present in the response JSON.
        """
        result = await self.call_get(f"/users/{username}")

        if result.status_code == 200:
            return result.json()["type"]

    async def get_own_repos(self):
        """Retrieve all repositories where the user is the owner or a collaborator."""

        repos = []

        get_params = {"affiliation": "collaborator,owner", "per_page": 100, "page": 1}

        result = await self.call_get("/user/repos", params=get_params)
        if result.status_code == 200:
            listing = result.json()
            repos.extend(
                [repo["full_name"] for repo in listing if not repo["archived"]]
            )

            # Check if there are more pages
            while len(listing) == 100:
                get_params["page"] += 1
                result = await self.call_get("/user/repos", params=get_params)
                if result.status_code == 200:
                    listing = result.json()
                    repos.extend(
                        [repo["full_name"] for repo in listing if not repo["archived"]]
                    )
        return repos

    async def get_user_repos(self, username: str):
        """Retrieve all repositories belonging to the user."""

        repos = []

        get_params = {"type": "owner", "per_page": 100, "page": 1}

        result = await self.call_get(f"/users/{username}/repos", params=get_params)
        if result.status_code == 200:
            listing = result.json()
            repos.extend(
                [repo["full_name"] for repo in listing if not repo["archived"]]
            )

            # Check if there are more pages
            while len(listing) == 100:
                get_params["page"] += 1
                result = await self.call_get(
                    f"/users/{username}/repos", params=get_params
                )
                if result.status_code == 200:
                    listing = result.json()
                    repos.extend(
                        [repo["full_name"] for repo in listing if not repo["archived"]]
                    )
        return repos

    async def get_organization_details(self, org: str):
        """Query the GitHub API for details about the specific organization.

        If the token has an org admin scope, then this will reveal additional
        information about the org.

        Args:
            org (str): Name of the GitHub organization.
        Returns:
            dict: Dictionary containing the organization's details from the
            GitHub API.
        """
        result = await self.call_get(f"/orgs/{org}")

        if result.status_code == 200:
            org_info = result.json()

            return org_info

        elif result.status_code == 404:
            logger.info(
                f"The organization {org} was not found or there is a permission issue!"
            )

    async def validate_sso(self, org: str, repository: str):
        """Query a repository in the organization to determine if SSO has been
        enabled for this PAT.

        If the query returns a 403 and an error message of "Resource protected
        by organization SAML enforcement. You must grant your Personal Access
        token access to this organization." then the PAT does not have
        permissions to this organization.

        Args:
            repository (str): Repository name in org/Repo format.
        Returns:
            bool: True if the organization is accessible either because SSO is
            not enabled, or if the PAT has been validated with SSO to that
            organization.
        """
        org_repos = await self.call_get(f"/orgs/{org}/repos")

        if org_repos.status_code != 200:
            logger.warning(
                "SSO does not seem to be enabled for this PAT!"
                " Error message:"
                f" {org_repos.json()['message']}"
            )
            return False

        result = await self.call_get(f"/repos/{repository}")
        if result.status_code == 403:
            logger.warning(
                "SSO does not seem to be enabled for this PAT! However,"
                "this PAT does have some access to the GitHub Enterprise. "
                f"Error message: {result.json()['message']}"
            )
            return False
        else:
            return True

    async def check_org_runners(self, org: str):
        """Checks runners associated with an organization.

        This requires a token with the `admin:org` scope.

        Args:
            org (str): Name of the organization

        Returns:
            dict: Dictionary containing information about the runners.
        """
        result = await self.call_get(f"/orgs/{org}/actions/runners")

        if result.status_code == 200:
            runner_info = result.json()
            if runner_info["total_count"] > 0:
                return runner_info
        else:
            logger.warning(
                f"Unable to query runners for {org}! This is likely due to the"
                " PAT permission level!"
            )

    async def get_org_repo_names_graphql(self, org: str, type: str):
        """Retrieve repositories within an organization using GraphQL."""
        repo_names = []
        if type not in ["PUBLIC", "PRIVATE"]:
            raise ValueError("Unsupported type!")

        cursor = None
        while True:
            query = {
                "query": GqlQueries.GET_ORG_REPOS,
                "variables": {"orgName": org, "repoTypes": type, "cursor": cursor},
            }

            response = await self.call_post("/graphql", query)
            if response.status_code == 200:
                response = response.json()
                repos = [
                    edge["node"]["name"]
                    for edge in response["data"]["organization"]["repositories"][
                        "edges"
                    ]
                ]
                repo_names.extend(repos)

                pageInfo = response["data"]["organization"]["repositories"]["pageInfo"]
                cursor = pageInfo["endCursor"] if pageInfo["hasNextPage"] else None

                if not pageInfo["hasNextPage"]:
                    break
            else:
                break

        return repo_names

    async def check_org_repos(self, org: str, repo_type: str):
        """Check repositories present within an organization.

        Args:
            org (str): Organization to check repositories for.
            private (bool, optional): Whether to only check private
            repositories. Defaults to True.

        Returns:
            list: List of dictionaries representing repositories within an
            organization.
        """
        if repo_type not in [
            "all",
            "public",
            "private",
            "forks",
            "sources",
            "member",
            "internal",
        ]:
            raise ValueError("Unsupported type!")
        repos = []

        org_details = await self.call_get(f"/orgs/{org}")
        # For public repos, Gato-X uses a fast GraphQL approach.
        if org_details.status_code == 200 and repo_type == "public":
            repo_count = org_details.json()["public_repos"]
            pub_repos = await DataIngestor.perform_parallel_repo_ingest(
                self, org, repo_count
            )
            repos.extend([repo for repo in pub_repos if not repo["archived"]])
            return repos

        get_params = {"type": repo_type, "per_page": 100, "page": 1}

        org_repos = await self.call_get(f"/orgs/{org}/repos", params=get_params)

        if org_repos.status_code == 200:
            listing = org_repos.json()

            repos.extend([repo for repo in listing if not repo["archived"]])
            # Check if there are more pages
            while len(listing) == 100:
                get_params["page"] += 1
                org_repos = await self.call_get(f"/orgs/{org}/repos", params=get_params)
                if org_repos.status_code == 200:
                    listing = org_repos.json()
                    repos.extend([repo for repo in listing if not repo["archived"]])
        else:
            logger.info(f"[-] {org} requires SSO!")
            return None

        return repos

    async def check_user(self):
        """Gets the authenticated user associated with a GitHub PAT and returns
        the username and available scopes.

        Format:

        {
            'user': username,
            'scopes': [ scope0, scope1, ...]
        }

        Returns:
            dict: User associated with the PAT, None otherwise.
        """
        result = await self.call_get("/user")
        if result.status_code == 200:
            resp_headers = result.headers.get("x-oauth-scopes")
            if resp_headers:
                scopes = [scope.strip() for scope in resp_headers.split(",")]
            else:
                scopes = []

            user_scopes = {
                "user": result.json()["login"],
                "scopes": scopes,
                "name": result.json()["name"],
            }

            return user_scopes
        else:
            logger.warning("Provided token was not valid or has expired!")

        return None

    async def get_repo_branch(self, repo: str, branch: str):
        """Check whether a specific branch exists on a remote.

        Args:
            repo (str): Name of the repository to check.
            branch (str): Name of the branch to check.

        Returns:
            int: Returns 1 upon success, 0 if the branch was not found, and -1
            if there was a failure retrieving the branch.
        """
        res = await self.call_get(f"/repos/{repo}/branches/{branch}")
        if res.status_code == 200:
            return 1
        elif res.status_code == 404:
            return 0
        else:
            logger.warning(f"Failed to check repo for branch! ({res.status_code}")
            return -1

    async def get_repo_runners(self, full_name: str):
        """Get self-hosted runners associated with the repository.

        Args:
            full_name (str): Name of the repository in Org/Repo format.

        Returns:
            list: List of self hosted runners from the repository.
        """
        runners = await self.call_get(f"/repos/{full_name}/actions/runners")

        if runners.status_code == 200:
            runner_list = runners.json()["runners"]
            return runner_list

        return []

    async def retrieve_run_logs(self, repo_name: str, workflows: list = []):
        """Retrieve the most recent run log associated with a repository.

        Args:
            repo_name (str): Full name of the repository.
            first instance of a non-ephemeral self-hosted runner is detected.
            Defaults to True.
            workflows (list, optional): List of workflows to check for. Defaults
            to empty list.
        Returns:
            list: List of run logs for runs that ran on self-hosted runners.
        """
        start_date = datetime.now() - timedelta(days=60)
        runs = []

        for workflow in workflows:
            # Get workflow runs for workflows we think have a sh runner.
            run_result = await self.call_get(
                f"/repos/{repo_name}/actions/workflows/{workflow}/runs",
                params={
                    "per_page": "3",
                    "status": "completed",
                    "exclude_pull_requests": "true",
                    "created": f">{start_date.isoformat()}",
                },
            )

            if run_result.status_code == 200:
                runs.extend(run_result.json()["workflow_runs"])

        # This is a dictionary so we can de-duplicate runner IDs based on
        # the machine_name:runner_name.
        run_logs = {}
        names = set()
        total_attempts = 0

        if runs:
            logger.debug(f"Enumerating runs within {repo_name}")
        for run in runs:
            # We only look at 10 workflow logs.
            # If we haven't found a non-ephemeral runner it is unlikely we will.
            # Larger repos with complex matrix builds and reusable workflows
            # can have massive log sizes and we end up wasting a lot of time.
            if total_attempts > 10:
                break

            # We are only interested in runs that actually executed.
            if run["conclusion"] != "success" and run["conclusion"] != "failure":
                continue

            # We only look at one workflow run (for yaml) per branch
            workflow_key = f"{run['head_branch']}:{run['path']}"
            if workflow_key in names:
                continue
            names.add(workflow_key)
            run_log = await self.call_get(
                f"/repos/{repo_name}/actions/runs/{run['id']}/"
                f"attempts/{run['run_attempt']}/logs"
            )

            if run_log.status_code == 200:
                try:
                    run_log = await self.__process_run_log(run_log.content, run)
                    if run_log:
                        key = f"{run_log['machine_name']}:{run_log['runner_name']}"
                        run_logs[key] = run_log

                        if run_log["non_ephemeral"]:
                            return run_logs.values()
                except Exception:
                    logger.warning(
                        f"Failed to process run log for {repo_name} run "
                        f"{run['id']} attempt {run['run_attempt']}!"
                    )
            elif run_log.status_code == 410:
                break
            else:
                logger.debug(
                    f"Call to retrieve run logs from {repo_name} run "
                    f"{run['id']} attempt {run['run_attempt']} returned "
                    f"{run_log.status_code}!"
                )

            total_attempts += 1

        return run_logs.values()

    async def parse_workflow_runs(self, repo_name: str):
        """Returns the number of workflow runs associated with the repository.

        Args:
            repo_name (str): Name of the repository in Org/Repo format to parse
            workflow runs for.

        Returns:
            int: Number of workflow runs associated with the repository, None
            if there was a failure.
        """
        runs = await self.call_get(f"/repos/{repo_name}/actions/runs")

        if runs.status_code == 200:
            return runs.json()["total_count"]
        else:
            logger.warning("Unable to query workflow runs.")

        return None

    async def get_recent_workflow(
        self, repo_name: str, sha: str, file_name: str, time_after=None
    ) -> int:
        """
        This function is used to get the most recent workflow from a GitHub repository.

        Parameters:
            repo_name (str): The name of the repository. It should be in the format 'owner/repo'.
            sha (str): The SHA of the commit for which to get the workflow.
            file_name (str): The name of the workflow file (without the .yml extension).
            time_after (str, optional): A timestamp in ISO 8601 format:
            YYYY-MM-DDTHH:MM:SSZ. Only show workflows updated after this time.

        Returns:
            int: The ID of the workflow if found, 0 if no workflows are found, or -1
            if there was an error querying the workflows.

        Raises:
            None

        Example:
            get_recent_workflow(
            'octocat/Hello-World',
            '7fd1a60b01f91b314f59955a4e4d4e80d8edf11d', 'test_workflow'
        )
        """
        params = {"head_sha": sha}

        if time_after:
            params["created"] = time_after

        req = await self.call_get(f"/repos/{repo_name}/actions/runs", params=params)

        if req.status_code != 200:
            logger.warning("Unable to query workflow runs.")
            return -1

        data = req.json()

        if data["total_count"] == 0:
            return 0

        # Find the id of the workflow
        for workflow in data["workflow_runs"]:
            if f".github/workflows/{file_name}.yml" in workflow["path"]:
                return workflow["id"]

        return 0

    async def get_workflow_status(self, repo_name: str, workflow_id: int):
        """Returns the status if the workflow by id.

        Args:
            repo_name (str): Name of the repository that has the workflow.
            workflow_id (int): ID of the workflow.

        Returns:
            int: 1 if the workflow has completed, 0 if it is pending, and -1 if
            there was a failure.
        """
        req = await self.call_get(f"/repos/{repo_name}/actions/runs/{workflow_id}")

        if req.status_code != 200:
            logger.warning("Unable to query the workflow.")
            return -1

        data = req.json()

        if data.get("status", "queued") in ["queued", "in_progress"]:
            return 0
        return 1 if data.get("conclusion", "failure") == "success" else -1

    async def delete_workflow_run(self, repo_name: str, workflow_id: int):
        """Deletes a previous workflow run.

        Args:
            repo_name (str): Name of the repository that has the workflow.
            workflow_id (int): ID of the workflow.

        Returns:
            bool: True if the workflow was deleted, false otherwise.
        """
        req = await self.call_delete(f"/repos/{repo_name}/actions/runs/{workflow_id}")

        return req.status_code == 204

    async def download_workflow_logs(self, repo_name: str, workflow_id: int):
        """Download worfklow run logs and saves them to a zip file under the
        workflow ID.

        Args:
            repo_name (str): Name of the repository that has the workflow.
            workflow_id (int): ID of the workflow.

        Returns:
            bool: True of the workflow log was downloaded, false otherwise.
        """
        req = await self.call_get(f"/repos/{repo_name}/actions/runs/{workflow_id}/logs")

        if req.status_code != 200:
            return False

        with open(f"{workflow_id}.zip", "wb+") as f:
            f.write(req.content)
        return True

    async def retrieve_workflow_log(
        self, repo_name: str, workflow_id: int, job_name: str
    ):
        """Download single run log and returns the text output from the zip.

        Args:
            repo_name (str): Name of the repository that has the workflow.
            workflow_id (int): ID of the workflow.
            job_name (str): Name of job to get output from.
        Returns:
            str: String content of the run log matching the job name, if found.
        """
        req = await self.call_get(f"/repos/{repo_name}/actions/runs/{workflow_id}/logs")

        if req.status_code != 200:
            return False

        return await self.__get_full_runlog(req.content, job_name)

    async def retrieve_workflow_artifact(self, repo_name: str, workflow_id: int):
        """Download workflow artifacts and return the files. Only use this for
        small artifacts, as this extracts the zip in memory.

        Args:
            repo_name (str): Name of the repository that has the workflow.
            workflow_id (int): ID of the workflow.
        Returns:

        """
        files = {}

        req = await self.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/artifacts"
        )
        if req.status_code != 200:
            return False

        artifacts = req.json().get("artifacts", [])

        if artifacts:
            download_url = artifacts[0]["archive_download_url"]

            archive = await self.call_get(
                download_url.replace("https://api.github.com", "")
            )

            with zipfile.ZipFile(io.BytesIO(archive.content)) as artifact:
                for zipinfo in artifact.infolist():
                    with artifact.open(zipinfo) as run_log:
                        content = run_log.read()
                        files[zipinfo.filename] = content

        return files

    async def download_workflow_artifact(
        self, repo_name: str, workflow_id: int, destination: str
    ):
        """Download a workflow artifact and save it to the destination."""

        req = await self.call_get(
            f"/repos/{repo_name}/actions/runs/{workflow_id}/artifacts"
        )
        if req.status_code != 200:
            return False

        artifacts = req.json().get("artifacts", [])
        download_url = artifacts[0]["archive_download_url"]

        archive = await self.call_get(
            download_url.replace("https://api.github.com", "")
        )

        with open(destination, "wb") as f:
            f.write(archive.content)

            return destination

        return False

    async def create_branch(self, repo_name: str, branch_name: str):
        """Create a branch with the provided name.

        Args:
            repo_name (str): Name of repository in Org/Repo format.
            branch_name (str): Name of branch to create.
        """
        resp = await self.call_get(f"/repos/{repo_name}")
        default_branch = resp.json()["default_branch"]
        resp = await self.call_get(f"/repos/{repo_name}/git/ref/heads/{default_branch}")

        json_resp = resp.json()
        sha = json_resp["object"]["sha"]

        branch_data = {"ref": f"refs/heads/{branch_name}", "sha": sha}

        resp = await self.call_post(f"/repos/{repo_name}/git/refs", params=branch_data)

        if resp.status_code == 201:
            return True
        else:
            return False

    async def delete_branch(self, repo_name: str, branch_name: str):
        """Deletes the specified branch within the repository.

        Args:
            repo_name (str): Name of the repository in Owner/Repo format.
            branch_name (str): Name of the branch to delete.
        """
        resp = await self.call_delete(
            f"/repos/{repo_name}/git/refs/heads/{branch_name}"
        )

        if resp.status_code == 204:
            return True

    async def commit_file(
        self,
        repo_name: str,
        branch_name: str,
        file_path: str,
        file_content: bytes,
        commit_author: str = "Gato-X",
        commit_email: str = "gato-x@pwn.com",
        message="Testing",
    ):
        """Commits a file to the specified branch on a repository.

        Args:
            repo_name (str): Name of repository to target.
            branch_name (str): Branch name to commit to. Must exist, otherwise
            the operation will fail.
            file_path (str): Path within to repository to commit file to.
            file_content (bytes): Content of the file to commit in bytes.
            commit_author (str): Author of the commit.
            commit_email (str): Email for commit.
            message (str): Commit message for testing.
        """
        b64_contents = base64.b64encode(file_content)
        commit_data = {
            "message": message,
            "content": b64_contents.decode("utf-8"),
            "branch": branch_name,
            "committer": {"name": commit_author, "email": commit_email},
        }

        resp = await self.call_put(
            f"/repos/{repo_name}/contents/{file_path}", params=commit_data
        )

        if resp.status_code == 201:
            resp_json = resp.json()
            return resp_json["commit"]["sha"]
        else:
            logger.debug(resp.status_code)
            logger.debug(resp.text)

    async def retrieve_workflow_ymls(self, repo_name: str):
        """Retrieve all .yml or .yaml files within the workflows directory.
        Utilizes the GitHub Repository contents API.

        Args:
            repo_name (str): Name of the repository in Org/Repo format.

        Returns:
            (list): List of yml files in text format.
        """
        ymls = []

        resp = await self.call_get(f"/repos/{repo_name}/contents/.github/workflows")

        if resp.status_code == 200:
            objects = resp.json()
            semaphore = asyncio.Semaphore(50)

            async def fetch_file(file):
                async with semaphore:
                    resp_file = await self.call_get(
                        f"/repos/{repo_name}/contents/{file['path']}"
                    )
                    if resp_file.status_code == 200:
                        resp_data = resp_file.json()
                        if "content" in resp_data:
                            file_data = base64.b64decode(resp_data["content"])
                            return Workflow(repo_name, file_data, file["name"])
                    return None

            tasks = [
                asyncio.create_task(fetch_file(file))
                for file in objects
                if file["type"] == "file"
                and (file["name"].endswith(".yml") or file["name"].endswith(".yaml"))
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ymls = [wf for wf in results if wf is not None]

        return ymls

    async def retrieve_workflow_ymls_ref(self, repo_name: str, ref: str):
        """Retrieve workflow files from a specific Git reference.

        Args:
            repo_name (str): Repository in Org/Repo format.
            ref (str): Commit SHA or branch name to pull workflows from.

        Returns:
            list[Workflow]: List of workflow wrappers.
        """
        ymls = []

        objects = []

        resp = await self.call_get(
            f"/repos/{repo_name}/contents/.github/workflows",
            params={"ref": ref},
        )

        if resp.status_code == 200:
            objects = resp.json()
        else:
            logger.warning(
                f"Failed to retrieve workflows from {repo_name} at ref {ref}!"
            )

        if objects:
            semaphore = asyncio.Semaphore(50)

            async def fetch_file(file):
                async with semaphore:
                    resp_file = await self.call_get(
                        f"/repos/{repo_name}/contents/{file['path']}",
                        params={"ref": ref},
                    )
                    if resp_file.status_code == 200:
                        resp_data = resp_file.json()
                        if "content" in resp_data:
                            file_data = base64.b64decode(resp_data["content"])
                            return Workflow(repo_name, file_data, file["name"])
                    return None

            tasks = [
                asyncio.create_task(fetch_file(file))
                for file in objects
                if file["type"] == "file"
                and (file["name"].endswith(".yml") or file["name"].endswith(".yaml"))
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            ymls = [wf for wf in results if wf is not None]

        return ymls

    async def retrieve_repo_file(
        self, repo_name: str, file_path: str, ref: str, public=False
    ):
        """Retrieves a single file from a GitHub repository.

        If the repository is public, it instead uses the raw.githubusercontent.com
        endpoint to save on the API rate limit.
        """
        file_data = None

        if public:
            file_data = await self.__get_raw_file(repo_name, file_path, ref)
        else:
            resp = await self.call_get(
                f"/repos/{repo_name}/contents/{file_path}", params={"ref": ref}
            )
            if resp.status_code == 200:
                resp_data = resp.json()
                if "content" in resp_data:
                    file_data = base64.b64decode(resp_data["content"])

        if file_data:
            return Workflow(
                repo_name,
                file_data,
                file_path.rsplit("/", 1)[-1],
                non_default=ref,
                special_path=file_path,
            )

    async def retrieve_workflow_yml(self, repo_name: str, workflow_name: str):
        """Retrieve all .yml or .yaml files within the workflows directory.
        Utilizes the GitHub Repository contents API.

        Args:
            repo_name (str): Name of the repository in Org/Repo format.
            workflow_name (str): Name of the workflow

        Returns:
            (list): List of yml files in text format.
        """
        resp = await self.call_get(
            f"/repos/{repo_name}/contents/.github/workflows/{workflow_name}"
        )

        if resp.status_code == 200:
            resp_data = resp.json()
            if "content" in resp_data:
                file_data = base64.b64decode(resp_data["content"])
                return Workflow(repo_name, file_data, workflow_name)
        else:
            raise ValueError(
                f"Failed to retrieve workflow {workflow_name} from {repo_name}!"
            )

    async def get_secrets(self, repo_name: str):
        """Issues an API call to the GitHub API to list secrets for a
        repository. This will succeed as long as the token has the repo scope
        and the user has write access to the repository.

        Args:
            repo_name (str): Name of repository to list secrets for.
        Returns:
            (list): List of secrets at the repo level, empty list if none.
        """
        secrets = []

        resp = await self.call_get(f"/repos/{repo_name}/actions/secrets")
        if resp.status_code == 200:
            secrets_response = resp.json()

            if secrets_response["total_count"] > 0:
                secrets = secrets_response["secrets"]

        return secrets

    async def get_environment_secrets(self, repo_name: str, environment_name: str):
        """Issues an API call to the GitHub API to list secrets for a specific
        environment within a repository. This requires the token to have the repo
        scope and the user to have write access to the repository and environment.

        Args:
            repo_name (str): Name of the repository.
            environment_name (str): Name of the environment to list secrets for.

        Returns:
            list: List of secrets at the environment level, empty list if none.
        """
        secrets = []

        environment_name = environment_name.replace("/", "%2F")
        resp = await self.call_get(
            f"/repos/{repo_name}/environments/{environment_name}/secrets"
        )
        if resp.status_code == 200:
            secrets_response = resp.json()

            if secrets_response["total_count"] > 0:
                secrets = secrets_response["secrets"]

        return secrets

    async def get_org_secrets(self, org_name: str):
        secrets = []

        resp = await self.call_get(f"/orgs/{org_name}/actions/secrets")
        if resp.status_code == 200:
            secrets_response = resp.json()

            if secrets_response["total_count"] > 0:
                for secret in secrets_response["secrets"]:
                    if secret["visibility"] == "selected":
                        repos_resp = await self.call_get(
                            f"/orgs/{org_name}/actions/secrets/"
                            f"{secret['name']}/repositories"
                        )

                        if repos_resp.status_code == 200:
                            repos_json = repos_resp.json()
                            repo_names = [
                                repo["full_name"] for repo in repos_json["repositories"]
                            ]

                        secret["repos"] = repo_names

                    secrets.append(secret)

        return secrets

    async def get_repo_org_secrets(self, repo_name: str):
        """Issues an API call to the GitHub API to list org secrets for a
        repository. This will succeed as long as the token has the repo scope
        and the user has write access to the repository.

        Args:
            repo_name (str): Name of repository to list secrets for.

        Returns:
            (list): List of org secrets that can be read via a workflow in this
            repository.
        """
        resp = await self.call_get(f"/repos/{repo_name}/actions/organization-secrets")
        secrets = []
        if resp.status_code == 200:
            secrets_response = resp.json()

            if secrets_response["total_count"] > 0:
                secrets = secrets_response["secrets"]

        return secrets

    async def get_file_last_updated(self, repo_name: str, file_path: str):
        resp = await self.call_get(
            f"/repos/{repo_name}/commits", params={"path": file_path, "per_page": 1}
        )

        commit_date = resp.json()[0]["commit"]["author"]["date"]
        commit_author = resp.json()[0]["commit"]["author"]["name"]
        commit_sha = resp.json()[0]["sha"]

        return commit_date, commit_author, commit_sha

    async def get_all_environment_protection_rules(self, repo_name: str):
        """
        Query all environments for a GitHub repository and return the combined protection rules array.

        Args:
            repo_name (str): The name of the repository.

        Returns:
            list: The combined protection rules array from all environments.
        """
        response = await self.call_get(f"/repos/{repo_name}/environments")

        all_protection_rules = []

        if response.status_code == 200:
            all_environments = response.json()

            for environment in all_environments["environments"]:
                protection_rules = environment.get("protection_rules", [])
                all_protection_rules.extend(
                    [
                        environment["name"]
                        for rule in protection_rules
                        if rule["type"] == "required_reviewers"
                    ]
                )

        return all_protection_rules

    async def commit_workflow(
        self,
        repo_name: str,
        target_branch: str,
        workflow_contents: bytes,
        file_name: str,
        commit_author: str = "Gato-X",
        commit_email: str = "Gato-X@pwn.com",
        message="Testing",
    ):
        """
        Commits a new workflow file to a specified repository.

        This function performs the following steps:
        1. Gets the latest commit SHA of the target branch.
        2. Gets the tree SHA of the latest commit of the new branch.
        3. Gets the tree of the .github/workflows directory.
        4. If the workflows tree exists, it gets the SHA of the workflows tree.
        5. Creates a new tree where all blobs in the .github/workflows tree are removed.
        6. Creates a new commit on the new branch with the new tree.
        7. Updates the new branch to point to the new commit.

        Args:
            repo_name (str): The name of the repository.
            target_branch (str): The name of the target branch.
            workflow_contents (bytes): The content of the new workflow file.
            file_name (str): The name of the new workflow file.
            commit_author (str, optional): The author of the commit. Defaults to "Gato".
            commit_email (str, optional): The email of the commit author. Defaults to "gato@gato.infosec".
            message (str, optional): The commit message. Defaults to "Testing".

        Returns:
            str: The SHA of the new commit if the commit was successful, None otherwise.
        """
        # Step 1: Get latest commit SHA of target branch
        r = await self.call_get(f"/repos/{repo_name}")
        if self.__verify_result(r, 200) is False:
            return None
        default_branch = r.json()["default_branch"]

        r = await self.call_get(f"/repos/{repo_name}/commits/{default_branch}")
        if self.__verify_result(r, 200) is False:
            return None
        latest_commit_sha = r.json()["sha"]

        # Step 2: Get tree SHA of latest commit of default
        r = await self.call_get(f"/repos/{repo_name}/git/commits/{latest_commit_sha}")
        if self.__verify_result(r, 200) is False:
            return None
        tree_sha = r.json()["tree"]["sha"]
        # Step 3: Get the tree of the .github/workflows directory
        r = await self.call_get(
            f"/repos/{repo_name}/git/trees/{tree_sha}", params={"recursive": "1"}
        )
        if self.__verify_result(r, 200) is False:
            return None

        tree_info = r.json()
        base_sha = tree_info["sha"]
        tree = tree_info["tree"]

        existing_files = (
            item
            for item in tree
            if ".github/workflows" in item["path"] and item["type"] == "blob"
        )

        # Step 4: Create a new tree where all blobs in the .github/workflows
        # tree are removed
        new_workflow_file_content = base64.b64encode(workflow_contents).decode()

        r = await self.call_post(
            f"/repos/{repo_name}/git/blobs",
            params={"content": new_workflow_file_content, "encoding": "base64"},
        )
        if self.__verify_result(r, 201) is False:
            return None

        new_tree = [
            {
                "path": f".github/workflows/{file_name}",
                "mode": "100644",
                "type": "blob",
                "sha": r.json()["sha"],
            }
        ]

        # Delete everything else
        for existing in existing_files:
            # Don't delete the same file - this will happen if the workflow
            # already exists (such as a test.yml file)
            if existing["path"] == f".github/workflows/{file_name}":
                continue

            new_tree.append(
                {
                    "path": existing["path"],
                    "mode": existing["mode"],
                    "type": existing["type"],
                    "sha": None,
                }
            )

        r = await self.call_post(
            f"/repos/{repo_name}/git/trees",
            params={"base_tree": base_sha, "tree": new_tree},
        )
        if self.__verify_result(r, 201) is False:
            return None
        new_tree_sha = r.json()["sha"]
        # Step 5: Create new commit on new branch
        r = await self.call_post(
            f"/repos/{repo_name}/git/commits",
            params={
                "message": message,
                "tree": new_tree_sha,
                "parents": [latest_commit_sha],
                "author": {"name": commit_author, "email": commit_email},
            },
        )
        new_commit_sha = r.json()["sha"]

        # Step 6: Update the new branch to point to the new commit
        r = await self.call_post(
            f"/repos/{repo_name}/git/refs",
            params={"sha": new_commit_sha, "ref": f"refs/heads/{target_branch}"},
        )
        if self.__verify_result(r, 201) is False:
            return None

        return new_commit_sha

    async def backtrack_head(self, repo_name, ref_name, commit_depth):
        """Uses the Git database API to revert a number of commits back from head.

        This essentially does:

            git reset --hard HEAD~<COMMIT_DEPTH>
            git push --force

        This is used for force pushing off payloads when conducting attacks
        in order to close the pull request.
        """

        params = {"sha": ref_name, "per_page": commit_depth + 1}

        resp = await self.call_get(f"/repos/{repo_name}/commits", params=params)

        if resp.status_code == 200:
            commits = resp.json()
            target = commits[commit_depth]["sha"]
        else:
            return False

        resp = await self.call_patch(
            f"/repos/{repo_name}/git/refs/heads/{ref_name}",
            params={"sha": target, "force": True},
        )

        if resp.status_code == 200:
            return True
        else:
            return False

    async def issue_dispatch(
        self, repo_name, target_workflow, target_branch, dispatch_inputs
    ):
        """Issues a workflow dispatch event to trigger a workflow.

        Args:
            repo_name (str): Name of the repository in Org/Repo format.
            target_workflow (str): Name of the workflow to trigger.
        """
        r = await self.call_post(
            f"/repos/{repo_name}/actions/workflows/{target_workflow}/dispatches",
            params={"ref": target_branch, "inputs": dispatch_inputs},
        )

        return r.status_code == 204

    async def get_issue_comments(self, repo_name, target_pr):
        """Receives the last 5 comments on the PR within the last minute.

        Args:
            repo_name (str): Name of the repository in Org/Repo format.
            target_pr (int): PR number to get comments for.
        """

        since = (
            (datetime.now(datetime.UTC) - timedelta(minutes=1))
            .replace(microsecond=0)
            .isoformat()
        )
        params = {"per_page": 5, "since": since + "Z"}

        r = await self.call_get(
            f"/repos/{repo_name}/issues/{target_pr}/comments", params=params
        )

        return r.json()

    async def create_repository(self, repository_name: str):
        """Creates a private repository for the authenticated user."""

        params = {"private": True, "name": repository_name}

        response = await self.call_post("/user/repos", params=params)

        if response.status_code == 201:
            return response.json()["full_name"]
        else:
            return False

    async def create_pull_request(
        self,
        source_repo: str,
        source_branch: str,
        target_repo: str,
        target_banch: str,
        pr_body="",
        pr_title="CI Test",
        draft=True,
    ):
        """
        This function is used to create a pull request on GitHub.

        Parameters:
            source_repo (str): The name of the source repository. It should be in the format 'owner/repo'.
            source_branch (str): The name of the source branch.
            target_repo (str): The name of the target repository. It should be in the format 'owner/repo'.
            target_banch (str): The name of the target branch.
            pr_body (str, optional): The body of the pull request. Default is an empty string.
            pr_title (str, optional): The title of the pull request. Default is 'CI Test'.
            draft (bool, optional): Whether the pull request should be created as a draft. Default is True.

        Returns:
            str: The URL of the created pull request if successful, False otherwise.

        Raises:
            None

        Example:
            create_pull_request('octocat/Hello-World', 'feature-branch', 'octocat/Hello-World', 'main', pr_body='This is a test PR', pr_title='Test PR', draft=False)
        """

        params = {
            "title": pr_title,
            "body": pr_body,
            "head": source_branch,
            "base": target_banch,
            "head_repo": source_repo,
            "draft": draft,
        }

        response = await self.call_post(f"/repos/{target_repo}/pulls", params=params)

        if response.status_code == 201:
            return response.json()["html_url"]
        else:
            return False

    async def retrieve_raw_action(self, repo: str, file_path: str, ref: str):
        """Retrieves a GitHub action yaml file from a public repository."""
        if file_path.endswith(".yml") or file_path.endswith(".yaml"):
            file_path = file_path.replace("//", "/")
            paths = [file_path]
        else:
            if file_path and not file_path.endswith("/"):
                file_path += "/"
            elif file_path.endswith("//"):
                file_path = file_path.replace("//", "/")
            paths = [f"{file_path}action.yml", f"{file_path}action.yaml"]

        # Try the raw request first (no RL)
        for path in paths:
            res = await self.__get_raw_file(repo, path, ref)

            if res:
                return res

        # Then drop to auth if it fails (consumes RL)
        for path in paths:
            resp = await self.call_get(
                f"/repos/{repo}/contents/{path}", params={"ref": ref}
            )

            if resp.status_code == 200:
                resp_data = resp.json()
                if "content" in resp_data:
                    file_data = base64.b64decode(resp_data["content"]).decode()
                    return file_data

        return None

    async def get_installation_repos(self):
        """ """
        response = await self.call_get("/installation/repositories")
        if response.status_code == 200:
            return response.json()

    async def get_commit_merge_date(self, repo: str, sha: str):
        """Gets the date of the merge commit."""

        query = {
            "query": GqlQueries.GET_PR_MERGED,
            "variables": {
                "sha": sha,
                "repo": repo.split("/")[1],
                "owner": repo.split("/")[0],
            },
        }

        r = await self.call_post("/graphql", params=query)
        if r.status_code == 200:
            response = r.json()

            if not response["data"]["repository"]:
                return None

            if not response["data"]["repository"]["commit"]["associatedPullRequests"][
                "edges"
            ]:
                return None

            pr_info = response["data"]["repository"]["commit"][
                "associatedPullRequests"
            ]["edges"][0]["node"]

            if pr_info["merged"]:
                return pr_info["mergedAt"]

    async def get_app_installations(self):
        """Get all installations for the GitHub App."""
        response = await self.call_get("/app/installations")
        if response.status_code == 200:
            return response.json()
        return None

    async def get_installation_access_token(self, installation_id: str):
        """Get an access token for a specific installation."""
        response = await self.call_post(
            f"/app/installations/{installation_id}/access_tokens"
        )
        if response.status_code == 201:
            return response.json()
        return None

    async def get_installation_info(self, installation_id: str):
        """Get detailed information about a specific installation."""
        response = await self.call_get(f"/app/installations/{installation_id}")
        if response.status_code == 200:
            return response.json()
        return None

    async def get_installation_repositories(self, installation_id: str):
        """Get repositories accessible to a specific installation."""
        response = await self.call_get(
            f"/app/installations/{installation_id}/repositories"
        )
        if response.status_code == 200:
            return response.json()
        return None

    async def get_app_info(self):
        """Get information about the GitHub App."""
        response = await self.call_get("/app")
        if response.status_code == 200:
            return response.json()
        return None

    async def invite_collaborator(self, repo: str, username: str, permission: str = "push"):
        """Invite a collaborator to a repository.
        
        Args:
            repo (str): Repository in org/repo format
            username (str): GitHub username to invite
            permission (str): Permission level (pull, push, admin, maintain, triage)
            
        Returns:
            bool: True if successful, False otherwise
        """
        params = {
            "permission": permission
        }
        
        response = await self.call_post(f"/repos/{repo}/collaborators/{username}", params=params)
        return response.status_code in [201, 204]

    async def create_deploy_key(self, repo: str, title: str, key: str, read_only: bool = True):
        """Create a deploy key for a repository.
        
        Args:
            repo (str): Repository in org/repo format
            title (str): Title for the deploy key
            key (str): SSH public key content
            read_only (bool): Whether the key should be read-only
            
        Returns:
            bool: True if successful, False otherwise
        """
        params = {
            "title": title,
            "key": key,
            "read_only": read_only
        }
        
        response = await self.call_post(f"/repos/{repo}/keys", params=params)
        return response.status_code == 201

    async def create_workflow_on_branch(self, repo: str, branch: str, filename: str, content: str, commit_message: str = "Add workflow"):
        """Create a workflow file on a specific branch.
        
        Args:
            repo (str): Repository in org/repo format
            branch (str): Branch name
            filename (str): Workflow filename
            content (str): Workflow file content
            commit_message (str): Commit message
            
        Returns:
            bool: True if successful, False otherwise
        """
        import base64
        
        # First, try to create the branch if it doesn't exist
        # Get the default branch SHA first
        repo_info = await self.get_repository(repo)
        if not repo_info:
            return False
            
        default_branch = repo_info.get("default_branch", "main")
        
        # Get the SHA of the default branch
        branch_info = await self.call_get(f"/repos/{repo}/git/ref/heads/{default_branch}")
        if branch_info.status_code != 200:
            return False
            
        default_sha = branch_info.json()["object"]["sha"]
        
        # Try to create the new branch
        create_branch_params = {
            "ref": f"refs/heads/{branch}",
            "sha": default_sha
        }
        
        await self.call_post(f"/repos/{repo}/git/refs", params=create_branch_params)
        # Don't check status code here - branch might already exist
        
        # Create the workflow file
        workflow_path = f".github/workflows/{filename}"
        encoded_content = base64.b64encode(content.encode()).decode()
        
        params = {
            "message": commit_message,
            "content": encoded_content,
            "branch": branch
        }
        
        response = await self.call_post(f"/repos/{repo}/contents/{workflow_path}", params=params)
        return response.status_code == 201
