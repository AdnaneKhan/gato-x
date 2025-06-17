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

import re
import logging


from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.issue_type import IssueType
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.github.api import Api
from gatox.workflow_parser.utility import CONTEXT_REGEX
from gatox.caching.cache_manager import CacheManager


logger = logging.getLogger(__name__)


class DispatchTOCTOUVisitor:
    """
    A visitor class designed to identify Time-Of-Check to Time-Of-Use (TOCTOU) vulnerabilities
    in GitHub workflows that are triggered via workflow dispatch and handle pull request numbers
    without accompanying SHA references.

    TOCTOU vulnerabilities can occur when there is a window of opportunity between the time a
    condition is checked and the time an action is taken based on that condition. This class
    specifically targets workflows that may be susceptible to such vulnerabilities by analyzing
    the paths within the workflow graph.
    """

    @staticmethod
    async def find_dispatch_misconfigurations(graph: TaggedGraph, api: Api):
        """
        Identifies TOCTOU vulnerabilities in workflows that are triggered by workflow dispatch
        events and handle pull request (PR) numbers without accompanying SHA references.

        This method performs the following operations:
        1. Retrieves all nodes tagged with "workflow_dispatch" from the workflow graph.
        2. For each of these nodes, it performs a Depth-First Search (DFS) to find paths
           that lead to nodes tagged with "checkout".
        3. Processes each identified path to determine if it contains potential TOCTOU
           vulnerabilities.
        4. Aggregates and renders the results in an ASCII format for easy visualization.

        Args:
            graph (TaggedGraph): The workflow graph containing all nodes and their relationships.
            api (Api): An instance of the API wrapper to interact with GitHub APIs.

        Returns:
            dict: Results containing any identified TOCTOU vulnerabilities organized by repository.

        Raises:
            Exception: Catches and logs any exceptions that occur during path processing.
        """
        nodes = graph.get_nodes_for_tags(["workflow_dispatch"])
        all_paths = []
        results = {}

        for cn in nodes:
            try:
                paths = await graph.dfs_to_tag(cn, "checkout", api)
                if paths:
                    all_paths.append(paths)
            except Exception as e:
                logger.error(f"Error finding paths for dispatch node: {str(e)}")
                logger.warning(f"Node: {cn}")

        for path_set in all_paths:
            for path in path_set:
                try:
                    await DispatchTOCTOUVisitor.__process_path(
                        path, graph, api, results
                    )
                except Exception as e:
                    logger.warning(f"Error processing path: {e}")
                    logger.warning(f"Path: {path}")

        return results

    @staticmethod
    async def __process_path(path, graph: TaggedGraph, api: Api, results: dict):
        """
        Processes a single path within the workflow graph to identify potential TOCTOU
        vulnerabilities.

        The processing involves:
        - Analyzing each node in the path to extract relevant information.
        - Maintaining lookups for input and environment variables.
        - Checking for mutable references that could lead to vulnerabilities.
        - Aggregating the findings into the results dictionary.

        Args:
            path (list): A list of nodes representing a single path in the workflow graph.
            graph (TaggedGraph): The workflow graph containing all nodes and their relationships.
            api (Api): An instance of the API wrapper to interact with GitHub APIs.
            results (dict): A dictionary to store the findings of the analysis.

        Returns:
            None

        Raises:
            Exception: Propagates any exceptions that occur during the processing of the path.
        """
        # Workflow dispatch jobs inherently have an approval gate,
        # so only TOCTOU issues can be exploited.
        input_lookup = {}
        env_lookup = {}
        flexible_lookup = {}

        for index, node in enumerate(path):
            tags = node.get_tags()

            if "JobNode" in tags:
                if node.outputs:
                    for o_key, val in node.outputs.items():
                        if "env." in val and val not in env_lookup:
                            for key in env_lookup.keys():
                                if key in val:
                                    flexible_lookup[o_key] = env_lookup[key]

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

                    # If the workflow dispatch node does not have any inputs,
                    # skip the rest of the path.
                    if not node.inputs:
                        break

                    pr_num_found = False
                    sha_found = False
                    # Process inputs to determine if any contain a PR number.
                    # This is a heuristic to identify workflows that are taking a PR number
                    # or mutable reference.
                    for key, val in node.inputs.items():
                        if "sha" in key.lower():
                            if isinstance(val, dict):
                                # Suppress if sha is required
                                if "required" in val:
                                    if val["required"]:
                                        sha_found = True

                        elif re.search(
                            r"(?:^|[\b_])(pr|pull|pull_request|pr_number)(?:[\b_]|$)",
                            key,
                            re.IGNORECASE,
                        ):
                            pr_num_found = True

                    if not pr_num_found or (pr_num_found and sha_found):
                        break

                    # Check workflow environment variables for GitHub event references
                    env_vars = node.get_env_vars()
                    for key, val in env_vars.items():
                        if isinstance(val, str):
                            if "github." in val:
                                env_lookup[key] = val

            elif "StepNode" in tags:
                if node.is_checkout:
                    checkout_ref = node.metadata
                    if "inputs." in node.metadata:
                        if "${{" in node.metadata:
                            processed_var = CONTEXT_REGEX.findall(node.metadata)
                            if processed_var:
                                processed_var = processed_var[0]
                                if "inputs." in processed_var:
                                    processed_var = processed_var.replace("inputs.", "")
                            else:
                                processed_var = node.metadata
                        else:
                            processed_var = node.metadata

                        if processed_var in env_lookup:
                            original_val = env_lookup[processed_var]
                            checkout_ref = original_val
                        elif processed_var in input_lookup:
                            checkout_ref = input_lookup[processed_var]

                    if VisitorUtils.check_mutable_ref(checkout_ref):
                        sinks = await graph.dfs_to_tag(node, "sink", api)
                        if sinks:
                            VisitorUtils.append_path(path, sinks[0])
                            VisitorUtils._add_results(
                                path,
                                results,
                                IssueType.DISPATCH_TOCTOU,
                                confidence=Confidence.HIGH,
                                complexity=Complexity.TOCTOU,
                            )
                        else:
                            VisitorUtils._add_results(
                                path,
                                results,
                                IssueType.DISPATCH_TOCTOU,
                                confidence=Confidence.LOW,
                                complexity=Complexity.TOCTOU,
                            )

            elif "ActionNode" in tags:
                await VisitorUtils.initialize_action_node(graph, api, node)
