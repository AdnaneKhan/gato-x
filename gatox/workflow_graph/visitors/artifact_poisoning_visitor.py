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

from gatox.caching.cache_manager import CacheManager
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.github.api import Api
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils

logger = logging.getLogger(__name__)


class ArtifactPoisoningVisitor:
    """Visits the graph to find potential artifact poisoning vulnerabilities.

    This is where the workflow runs on workflow_run, then downloads an
    artifact, extracts it, and then runs code from it.
    """

    @staticmethod
    async def __process_path(path: list, graph: TaggedGraph, api: Api, results):
        # This function processes a single path to find artifact poisoning.
        # It checks if the path contains a workflow_run node that downloads
        # an artifact and then uses it in an unsafe manner.
        input_lookup = {}

        for index, node in enumerate(path):
            tags = node.get_tags()

            if "WorkflowNode" in tags:
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
            elif "ActionNode" in tags:
                await VisitorUtils.initialize_action_node(graph, api, node)

                if "artifact" in node.get_tags():
                    # Terminal, we need to dfs to a sink now.
                    sinks = await graph.dfs_to_tag(node, "sink", api)
                    if sinks:

                        VisitorUtils.append_path(path, sinks[0])

                        VisitorUtils._add_results(
                            path,
                            results,
                            IssueType.ARTIFACT_POISONING,
                            complexity=Complexity.PREVIOUS_CONTRIBUTOR,
                            confidence=Confidence.MEDIUM,
                        )

    @staticmethod
    async def find_artifact_poisoning(graph: TaggedGraph, api: Api):
        # Unlike pwn requests, we are looking specifically
        # for cases of improper aritfact validation,
        # so we follow different logic focused on that.
        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(["workflow_run"])

        all_paths = []
        results = {}

        for cn in nodes:
            paths = await graph.dfs_to_tag(cn, "artifact", api)

            if paths:
                all_paths.append(paths)

        for path_set in all_paths:
            for path in path_set:
                try:

                    await ArtifactPoisoningVisitor.__process_path(
                        path, graph, api, results
                    )
                except Exception as e:
                    logger.warning(f"Error processing path: {e}")
                    logger.warning(f"Path: {path}")

        return results
