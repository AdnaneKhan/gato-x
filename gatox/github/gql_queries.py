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
    def get_workflow_ymls_from_list(repos: list, batch_size: int = 50):
        """
        Constructs a list of GraphQL queries to fetch workflow YAML
        files from a list of repositories.

        This method splits the list of repositories into chunks of
        up to batch_size repositories each, and constructs a separate
        GraphQL query for each chunk. Each query fetches the workflow
        YAML files from the repositories in one chunk.

        Args:
            repos (list): A list of repository slugs, where each
            slug is a string in the format "owner/name".
            batch_size (int, optional): Maximum number of repos per
            GraphQL query. Defaults to 50.

        Returns:
            tuple: (queries, repo_groups) where:
                queries (list): List of dicts with "query" key.
                repo_groups (list): List of lists, where
                repo_groups[i] contains the repo slugs from queries[i].
        """

        queries = []
        repo_groups = []

        for i in range(0, len(repos), batch_size):
            chunk = repos[i : i + batch_size]
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
            repo_groups.append(list(chunk))

        return queries, repo_groups

    @staticmethod
    def get_workflow_ymls(repos: list, batch_size: int = 50):
        """Retrieve workflow yml files for each repository.

        Args:
            repos (List[Repository]): List of repository objects
            batch_size (int, optional): Maximum number of repos per
            GraphQL query. Defaults to 50.

        Returns:
            tuple: (queries, repo_groups) where:
                queries (list): List of JSON post parameters for
                each GraphQL query.
                repo_groups (list): List of lists, where
                repo_groups[i] contains the Repository objects
                from queries[i].
        """
        queries = []
        repo_groups = []

        if len(repos) == 0:
            return queries, repo_groups

        for i in range(0, len(repos), batch_size):
            chunk = repos[i : i + batch_size]
            # Use reduce to accumulate node_ids and can_push in a single iteration
            node_ids, can_push = reduce(
                lambda acc, repo: (
                    acc[0] + [repo.repo_data["node_id"]],
                    acc[1] or repo.can_push(),
                ),
                chunk,
                ([], False),
            )

            query = {
                # We list envs if we have write access to one in the set (for secrets
                # reasons, otherwise we don't list them)
                "query": (GqlQueries.GET_YMLS_ENV if can_push else GqlQueries.GET_YMLS),
                "variables": {"node_ids": node_ids},
            }

            queries.append(query)
            repo_groups.append(list(chunk))

        return queries, repo_groups
