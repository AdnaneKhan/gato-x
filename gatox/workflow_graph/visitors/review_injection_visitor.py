"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.github.api import Api
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.workflow_parser.utility import (
    CONTEXT_REGEX,
    getToken,
    getTokens,
    prReviewUnsafe,
)


class ReviewInjectionVisitor:
    """
    This class implements a graph visitor tasked with identifying
    injection issues on the pull_request_review and
    pull_request_review comment triggers.
    """

    @staticmethod
    async def find_injections(graph: TaggedGraph, api: Api):
        """
        Identify potential injection vulnerabilities within GitHub workflows.

        This method analyzes the workflow graph to detect injection issues by
        examining paths from nodes tagged with relevant injection-related tags
        (e.g., "issue_comment", "pull_request_target") and checking for vulnerabilities
        based on environment variables and input parameters.

        The analysis involves:
        1. Retrieving all nodes tagged with specific injection-related tags from the workflow graph.
        2. For each of these nodes, performing a Depth-First Search (DFS) to find paths
           that lead to nodes tagged with "injectable".
        3. Iterating through each path and analyzing nodes to determine potential injection
           vulnerabilities based on variable handling and environment rules.
        4. Aggregating the results and rendering them in an ASCII format for easy visualization.

        Args:
            graph (TaggedGraph): The workflow graph containing all nodes and their relationships.
            api (Api): An instance of the API wrapper to interact with GitHub APIs.
            ignore_workflow_run (bool, optional): Flag to determine whether to ignore "workflow_run" tags. Defaults to False.

        Returns:
            None

        Raises:
            Exception: Logs any exceptions that occur during the processing of individual paths,
                       allowing the analysis to continue without interruption.
        """
        query_taglist = [
            "pull_request_review_comment",
            "pull_request_review",
        ]

        nodes = graph.get_nodes_for_tags(query_taglist)

        all_paths = []
        results = {}
        rule_cache = {}

        for cn in nodes:
            paths = await graph.dfs_to_tag(cn, "injectable", api)
            if paths:
                all_paths.append(paths)

        for path_set in all_paths:
            for path in path_set:
                input_lookup = {}
                env_lookup = {}
                flexible_lookup = {}

                approval_gate = False
                for index, node in enumerate(path):
                    tags = node.get_tags()

                    if "JobNode" in tags:
                        # Check deployment environment rules
                        if (
                            node.deployments
                            and await VisitorUtils.check_deployment_approval_gate(
                                node, rule_cache, api, input_lookup, env_lookup
                            )
                        ):
                            approval_gate = True
                            continue

                        paths = await graph.dfs_to_tag(node, "permission_check", api)
                        if paths:
                            approval_gate = True

                        env_vars = node.get_env_vars()
                        for key, val in env_vars.items():
                            if isinstance(val, str):
                                if "github." in val:
                                    env_lookup[key] = val

                        if node.outputs:
                            for o_key, val in node.outputs.items():
                                if not isinstance(val, str):
                                    continue

                                if "env." in val and val not in env_lookup:
                                    for key in env_lookup.keys():
                                        if key in val:
                                            flexible_lookup[o_key] = env_lookup[key]
                    elif "StepNode" in tags:
                        if "injectable" in tags:
                            # We need to figure out what variables are referenced.
                            # Also, need to consider the multi-tag DFS option
                            # because the true injection might be later.

                            if approval_gate is True:
                                continue

                            filtered_contexts = set()

                            # Now we go and try to resolve variables.
                            for variable in node.contexts:
                                if "inputs." in variable:
                                    if "${{" in variable:
                                        processed_var = CONTEXT_REGEX.findall(variable)
                                        if processed_var:
                                            processed_var = processed_var[0]
                                            if "inputs." in processed_var:
                                                processed_var = processed_var.replace(
                                                    "inputs.", ""
                                                )
                                    else:
                                        processed_var = variable

                                    if processed_var in env_lookup:
                                        original_val = env_lookup[processed_var]
                                        variable = original_val

                                    variable = getToken(variable)
                                    filtered_contexts.add(variable)

                                elif "env." in variable:
                                    for key, val in env_lookup.items():
                                        if key in variable:
                                            variable = val
                                            variable = getToken(variable)
                                            filtered_contexts.add(variable)
                                            break
                                else:
                                    filtered_contexts.add(variable)

                            for val in filtered_contexts:
                                if "${{" in val:
                                    val = getTokens(val)
                                    if val:
                                        val = val[0]

                                if "github." in val and not prReviewUnsafe(val):
                                    continue
                                elif prReviewUnsafe(val) or "body" in val:
                                    conf = Confidence.HIGH
                                    VisitorUtils._add_results(
                                        path,
                                        results,
                                        IssueType.PR_REVIEW_INJECTION,
                                        confidence=conf,
                                    )
                                    break
                    elif "WorkflowNode" in tags:
                        if index != 0 and "JobNode" in path[index - 1].get_tags():
                            # Caller job node
                            node_params = path[index - 1].params
                            # Set lookup for input params
                            input_lookup.update(node_params)
                        if index == 0:
                            # Check workflow environment variables.
                            # For env vars that are github.event.*
                            env_vars = node.get_env_vars()
                            for key, val in env_vars.items():
                                if isinstance(val, str):
                                    if "github." in val:
                                        env_lookup[key] = val
                    elif "ActionNode" in tags:
                        await VisitorUtils.initialize_action_node(graph, api, node)

                # Goal here is to start from the top and keep track
                # of any variables that come out of steps
                # or get passed through workflow calls.
                # We also want to ensure tracking inside of
                # composite actions.

        return results
