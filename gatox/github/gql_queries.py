from functools import reduce


class GqlQueries:
    """Constructs graphql queries for use with the GitHub GraphQL api."""

    GET_YMLS_WITH_SLUGS = """
    fragment repoWorkflows on Repository {
        nameWithOwner
        stargazers {
            totalCount
        }
        isPrivate
        isArchived
        viewerPermission
        forkingAllowed
        url
        isFork
        pushedAt
        defaultBranchRef {
            name
        }
        object(expression: "HEAD:.github/workflows/") {
            ... on Tree {
                entries {
                    name
                    type
                    mode
                    object {
                        ... on Blob {
                            byteSize
                            text
                        }
                    }
                }
            }
        }
    }
    """

    GET_YMLS = """
    query RepoFiles($node_ids: [ID!]!) {
        nodes(ids: $node_ids) {
            ... on Repository {
                nameWithOwner
                isPrivate
                isArchived
                forkingAllowed
                stargazers {
                    totalCount
                }
                viewerPermission
                pushedAt
                url
                isFork
                defaultBranchRef {
                    name
                }
                object(expression: "HEAD:.github/workflows/") {
                    ... on Tree {
                        entries {
                            name
                            type
                            mode
                            object {
                                ... on Blob {
                                    byteSize
                                    text
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    GET_YMLS_ENV = """
        query RepoFiles($node_ids: [ID!]!) {
            nodes(ids: $node_ids) {
                ... on Repository {
                    nameWithOwner
                    isPrivate
                    isArchived
                    forkingAllowed
                    stargazers {
                        totalCount
                    }
                    viewerPermission
                    pushedAt
                    url
                    isFork
                    environments(first: 100) {
                        edges {
                        node {
                            id
                            name
                        }
                    }
                    }
                    defaultBranchRef {
                        name
                    }
                    object(expression: "HEAD:.github/workflows/") {
                        ... on Tree {
                            entries {
                                name
                                type
                                mode
                                object {
                                    ... on Blob {
                                        byteSize
                                        text
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    """

    GET_ORG_REPOS = """
        query($orgName: String!, $repoTypes: RepositoryPrivacy!, $cursor: String) {
            organization(login: $orgName) {
                repositories(first: 100, privacy: $repoTypes, after: $cursor) {
                edges {
                    node {
                    name
                    }
                    cursor
                }
                pageInfo {
                    endCursor
                    hasNextPage
                }
                }
            }
            }
    """

    GET_PR_MERGED = """
    query associatedPRs($sha: String, $repo: String!, $owner: String!){
            repository(name: $repo, owner: $owner) {
                commit: object(expression: $sha) {
                ... on Commit {
                    associatedPullRequests(first:1){
                    edges{
                        node{
                        merged
                        mergedAt
                        }
                    }
                    }
                }
                }
            }
    }
    """

    @staticmethod
    def get_workflow_ymls_from_list(repos: list):
        """
        Constructs a list of GraphQL queries to fetch workflow YAML
        files from a list of repositories.

        This method splits the list of repositories into chunks of
        up to 100 repositories each, and constructs a separate
        GraphQL query for each chunk. Each query fetches the workflow
        YAML files from the repositories in one chunk.

        Args:
            repos (list): A list of repository slugs, where each
            slug is a string in the format "owner/name".

        Returns:
            list: A list of dictionaries, where each dictionary
            contains a single GraphQL query in the format:
            {"query": "<GraphQL query string>"}.
        """

        queries = []

        for i in range(0, len(repos), 50):
            chunk = repos[i : i + 50]
            repo_queries = []

            for j, repo in enumerate(chunk):
                owner, name = repo.split("/")
                repo_query = f"""
                repo{j + 1}: repository(owner: "{owner}", name: "{name}") {{
                    ...repoWorkflows
                }}
                """
                repo_queries.append(repo_query)

            queries.append(
                {
                    "query": GqlQueries.GET_YMLS_WITH_SLUGS
                    + "{\n"
                    + "\n".join(repo_queries)
                    + "\n}"
                }
            )

        return queries

    @staticmethod
    def get_workflow_ymls(repos: list):
        """Retrieve workflow yml files for each repository.

        Args:
            repos (List[Repository]): List of repository objects
        Returns:
            (list): List of JSON post parameters for each graphQL query.
        """
        queries = []

        if len(repos) == 0:
            return queries

        for i in range(0, (len(repos) // 100) + 1):
            top_len = len(repos) if len(repos) < 100 * (i + 1) else 100 * (i + 1)
            # Use reduce to accumulate node_ids and can_push in a single iteration
            node_ids, can_push = reduce(
                lambda acc, repo: (
                    acc[0] + [repo.repo_data["node_id"]],
                    acc[1] or repo.can_push(),
                ),
                repos[100 * i : top_len],
                ([], False),
            )

            query = {
                # We list envs if we have write access to one in the set (for secrets
                # reasons, otherwise we don't list them)
                "query": (GqlQueries.GET_YMLS_ENV if can_push else GqlQueries.GET_YMLS),
                "variables": {"node_ids": node_ids},
            }

            queries.append(query)
        return queries
