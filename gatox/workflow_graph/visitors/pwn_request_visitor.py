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

import logging

from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.issue_type import IssueType
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.github.api import Api
from gatox.caching.cache_manager import CacheManager

logger = logging.getLogger(__name__)


class PwnRequestVisitor:
    """Visits the graph to find potential Pwn Requests."""

    @staticmethod
    async def _process_single_path(path, graph, api, rule_cache, results):
        """
        Process a single path for potential security issues.
        This method analyzes a given path within the workflow graph to identify and flag
        potential security vulnerabilities related to Pwn (Privilege Escalation) requests.
        It inspects each node for specific tags, evaluates deployment environment rules,
        and determines if approval gates are required based on the analysis.
        Args:
            path (List[Node]):
                The sequence of nodes representing a potential security path to process.
            graph (TaggedGraph):
                The workflow graph containing all nodes and their relationships.
            api (Api):
                An instance of the API wrapper to interact with external services.
            rule_cache (dict):
                A cache storing environment protection rules for repositories to avoid redundant API calls.
            results (dict):
                A dictionary aggregating the detected security issues, organized by repository.
        Returns:
            None
        Raises:
            None
        """
        input_lookup = {}
        env_lookup = {}
        flexible_lookup = {}
        approval_gate = False
        blocker_nodes = set()  # Memoize blocker nodes found
        approval_gate_nodes = set()  # Memoize approval gate nodes found

        for index, node in enumerate(path):
            tags = node.get_tags()

            if "JobNode" in tags:
                # Check deployment environment rules
                if node.deployments:
                    if node.repo_name() in rule_cache:
                        rules = rule_cache[node.repo_name()]
                    else:
                        rules = await api.get_all_environment_protection_rules(
                            node.repo_name()
                        )
                        rule_cache[node.repo_name()] = rules
                    for deployment in node.deployments:
                        if isinstance(deployment, dict):
                            deployment = deployment["name"]
                        deployment = VisitorUtils.process_context_var(deployment)

                        if deployment in input_lookup:
                            deployment = input_lookup[deployment]
                        elif deployment in env_lookup:
                            deployment = env_lookup[deployment]

                        if deployment in rules:
                            approval_gate = True
                            continue

                paths = await graph.dfs_to_tag(node, "permission_blocker", api)
                if paths:
                    # Memoize the blocker nodes (last node in each path) instead of breaking
                    for blocker_path in paths:
                        if blocker_path:
                            blocker_nodes.add(blocker_path[-1])
                    logger.debug(
                        f"Found {len(paths)} permission blocker paths, memoized {len(blocker_nodes)} blocker nodes"
                    )

                paths = await graph.dfs_to_tag(node, "permission_check", api)
                if paths:
                    # Memoize the approval gate nodes (last node in each path)
                    for gate_path in paths:
                        if gate_path:
                            approval_gate_nodes.add(gate_path[-1])
                    logger.debug(
                        f"Found {len(paths)} permission check paths, memoized {len(approval_gate_nodes)} approval gate nodes"
                    )

                if node.outputs:
                    for o_key, val in node.outputs.items():
                        if not isinstance(val, str):
                            continue

                        if "env." in val and val not in env_lookup:
                            for key in env_lookup.keys():
                                if key in val:
                                    flexible_lookup[o_key] = env_lookup[key]

            elif "StepNode" in tags:
                if node.is_checkout:
                    # Terminal
                    checkout_ref = node.metadata
                    if "inputs." in node.metadata:
                        processed_var = VisitorUtils.process_context_var(node.metadata)
                        if processed_var in env_lookup:
                            original_val = env_lookup[processed_var]
                            checkout_ref = original_val
                        elif processed_var in input_lookup:
                            checkout_ref = input_lookup[processed_var]

                    elif "env." in node.metadata:
                        for key, val in env_lookup.items():
                            if key in node.metadata:
                                checkout_ref = val
                                break

                    if (
                        approval_gate
                        and VisitorUtils.check_mutable_ref(
                            checkout_ref, path[0].get_tags()
                        )
                    ) or not approval_gate:
                        sinks = await graph.dfs_to_tag(node, "sink", api)

                        if approval_gate:
                            complexity = Complexity.TOCTOU
                        elif "workflow_run" in path[0].get_tags():
                            complexity = Complexity.PREVIOUS_CONTRIBUTOR
                        else:
                            complexity = Complexity.ZERO_CLICK

                        complexity = Complexity.TOCTOU if approval_gate else complexity
                        if sinks:
                            VisitorUtils.append_path(path, sinks[0])
                            confidence = Confidence.HIGH
                        else:
                            confidence = Confidence.UNKNOWN

                        # Check if any blocker nodes or approval gate nodes are in the current path
                        path_nodes = set(path)
                        if sinks:
                            path_nodes.update(sinks[0])

                        has_blocker_in_path = bool(
                            blocker_nodes.intersection(path_nodes)
                        )
                        has_approval_gate_in_path = bool(
                            approval_gate_nodes.intersection(path_nodes)
                        )

                        # Update approval_gate based on whether approval gate nodes are actually in the path
                        # or if it was set by other conditions (deployments, soft gates, etc.)
                        effective_approval_gate = (
                            approval_gate or has_approval_gate_in_path
                        )

                        # Recalculate complexity based on effective approval gate
                        if effective_approval_gate:
                            complexity = Complexity.TOCTOU
                        elif "workflow_run" in path[0].get_tags():
                            complexity = Complexity.PREVIOUS_CONTRIBUTOR
                        else:
                            complexity = Complexity.ZERO_CLICK

                        logger.debug(
                            f"Path analysis: blocker_nodes={len(blocker_nodes)}, approval_gate_nodes={len(approval_gate_nodes)}, path_nodes={len(path_nodes)}, has_blocker_in_path={has_blocker_in_path}, has_approval_gate_in_path={has_approval_gate_in_path}, effective_approval_gate={effective_approval_gate}"
                        )

                        # Only add results if no blocker nodes are found in the path
                        if not has_blocker_in_path:
                            VisitorUtils._add_results(
                                path,
                                results,
                                IssueType.PWN_REQUEST,
                                complexity=complexity,
                                confidence=confidence,
                            )
                        else:
                            logger.debug(
                                "Suppressing results due to blocker node found in path"
                            )
                        break

                if node.outputs:
                    for key, val in node.outputs.items():
                        if "env." in val:
                            pass

                if node.hard_gate:
                    break

                if node.soft_gate:
                    approval_gate = True

            elif "WorkflowNode" in tags:
                if index != 0 and "JobNode" in path[index - 1].get_tags():
                    # Caller job node
                    node_params = path[index - 1].params
                    # Set lookup for input params
                    input_lookup.update(node_params)
                if index == 0:
                    repo = CacheManager().get_repository(node.repo_name())
                    if repo.is_fork():
                        break

                    if node.excluded():
                        break

                    if "pull_request_target:labeled" in tags:
                        approval_gate = True

                    # Check workflow environment variables
                    env_vars = node.get_env_vars()
                    for key, val in env_vars.items():
                        if isinstance(val, str) and "github." in val:
                            env_lookup[key] = val

            elif "ActionNode" in tags:
                await VisitorUtils.initialize_action_node(graph, api, node)

    @staticmethod
    async def find_pwn_requests(
        graph: TaggedGraph, api: Api, ignore_workflow_run=False
    ):
        """
        Identify and process potential Pwn Requests within the workflow graph.

        This method searches for paths within the workflow graph that could lead to
        privilege escalation vulnerabilities. It starts by querying nodes with specific
        tags related to pull requests and issues, then performs depth-first searches to
        locate checkout nodes, and processes each discovered path for potential security issues.

        Args:
            graph (TaggedGraph):
                The workflow graph containing all nodes and their relationships.
            api (Api):
                An instance of the API wrapper to interact with GitHub APIs.
            ignore_workflow_run (bool, optional):
                Determines whether to ignore nodes tagged with "workflow_run". Defaults to False.

        Returns:
            dict: Results containing any identified security issues organized by repository.

        Raises:
            None
        """
        query_taglist = [
            "issue_comment",
            "pull_request_target",
            "pull_request_target:labeled",
        ]

        if not ignore_workflow_run:
            query_taglist.append("workflow_run")

        # Retrieve all repository-related nodes with the specified tags
        nodes = graph.get_nodes_for_tags(query_taglist)
        all_paths = []
        results = {}
        rule_cache = {}

        for cn in nodes:
            try:
                paths = await graph.dfs_to_tag(cn, "checkout", api)
                if paths:
                    all_paths.append(paths)
            except Exception as e:
                logger.error(f"Error finding paths for pwn request node: {str(e)}")
                logger.error(f"Node: {cn}")

        for path_set in all_paths:
            for path in path_set:
                try:
                    await PwnRequestVisitor._process_single_path(
                        path, graph, api, rule_cache, results
                    )
                except Exception as e:
                    logger.warning(f"Error processing path: {str(e)}")
                    logger.warning(f"Path: {path}")

        return results
