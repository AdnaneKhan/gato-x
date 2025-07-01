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

import networkx as nx
import logging
import time

logger = logging.getLogger(__name__)

# Traversal monitoring constants
MAX_TRAVERSAL_TIME_SECONDS = 30  # Warn if traversal takes longer than 30 seconds
MAX_PATH_LENGTH = 100  # Warn if path length exceeds 100 nodes
MAX_NODES_VISITED = 1000  # Warn if more than 1000 nodes visited in single traversal


class TaggedGraph(nx.DiGraph):
    """
    A directed graph with tagging capabilities, extending NetworkX's DiGraph.

    This class allows nodes to be associated with multiple tags, enabling
    efficient querying and traversal based on these tags.
    """

    def __init__(self, builder, **attr):
        """
        Initialize the TaggedGraph.

        Parameters:
            builder: An instance responsible for building or modifying the graph.
            **attr: Arbitrary keyword arguments to initialize the graph.
        """
        super().__init__(**attr)
        self.builder = builder
        self.tags = {}  # Dictionary to map tags to sets of nodes

    async def dfs_to_tag(self, start_node, target_tag, api, ignore_depends=False):
        """
        Perform a Depth-First Search (DFS) from the start node to find all paths
        that lead to nodes with the specified target tag.

        Parameters:
            start_node: The node from which the DFS begins.
            target_tag (str): The tag to search for in reachable nodes.
            api: An instance of the API wrapper to interact with external services if needed.

        Returns:
            list: A list of all paths, where each path is a list of nodes leading to the target tag.
        """
        start_time = time.time()
        path = list()
        all_paths = list()
        visited = set()

        # Track traversal metrics
        traversal_stats = {
            "nodes_visited": 0,
            "max_path_length": 0,
            "start_node": start_node,
            "target_tag": target_tag,
            "start_time": start_time,
        }

        await self._dfs(
            start_node,
            target_tag,
            path,
            all_paths,
            visited,
            api,
            ignore_depends,
            traversal_stats,
        )

        # Log traversal completion and check for issues
        elapsed_time = time.time() - start_time
        self._log_traversal_completion(traversal_stats, elapsed_time, len(all_paths))

        return all_paths

    async def _dfs(
        self,
        current_node,
        target_tag,
        path,
        all_paths,
        visited,
        api,
        ignore_depends=False,
        traversal_stats=None,
    ):
        """
        Helper method to recursively perform DFS.

        Parameters:
            current_node: The current node in the DFS traversal.
            target_tag (str): The tag to search for.
            path (list): The current path of nodes being explored.
            all_paths (list): The list accumulating all valid paths found.
            visited (set): A set of nodes that have been visited in the current traversal.
            api: An instance of the API wrapper for external interactions.
            ignore_depends (bool): If True, ignore edges with the "depends" relation.
            traversal_stats (dict): Dictionary to track traversal metrics.

        Returns:
            None
        """
        if not all(req in path for req in current_node.get_needs()):
            return

        # Update traversal statistics
        if traversal_stats:
            traversal_stats["nodes_visited"] += 1
            current_time = time.time()

            # Check for excessive traversal time
            if (
                current_time - traversal_stats["start_time"]
                > MAX_TRAVERSAL_TIME_SECONDS
            ):
                logger.warning(
                    f"Graph traversal taking excessive time: {current_time - traversal_stats['start_time']:.2f}s. "
                    f"Start node: {traversal_stats['start_node']}, target: {traversal_stats['target_tag']}, "
                    f"nodes visited: {traversal_stats['nodes_visited']}, current path length: {len(path)}"
                )

            # Check for excessive nodes visited
            if traversal_stats["nodes_visited"] > MAX_NODES_VISITED:
                logger.warning(
                    f"Graph traversal visited excessive nodes: {traversal_stats['nodes_visited']}. "
                    f"This may indicate cycles or very complex graph structure. "
                    f"Start node: {traversal_stats['start_node']}, target: {traversal_stats['target_tag']}"
                )

        path.append(current_node)
        visited.add(current_node)

        # Update max path length seen
        if traversal_stats:
            traversal_stats["max_path_length"] = max(
                traversal_stats["max_path_length"], len(path)
            )

            # Check for excessive path length
            if len(path) > MAX_PATH_LENGTH:
                logger.warning(
                    f"Graph traversal path length excessive: {len(path)} nodes. "
                    f"This may indicate cycles or very deep graph structure. "
                    f"Start node: {traversal_stats['start_node']}, target: {traversal_stats['target_tag']}, "
                    f"current node: {current_node}"
                )

        if "uninitialized" in current_node.get_tags():
            await self.builder.initialize_node(current_node, api)

        if target_tag in current_node.get_tags():
            all_paths.append(list(path))
        else:
            for neighbor in self.neighbors(current_node):
                relation = self.get_edge_data(current_node, neighbor).get(
                    "relation", None
                )
                if relation and relation == "depends" and ignore_depends:
                    continue
                if neighbor not in visited:
                    await self._dfs(
                        neighbor,
                        target_tag,
                        path,
                        all_paths,
                        visited,
                        api,
                        ignore_depends,
                        traversal_stats,
                    )

        path.pop()
        visited.remove(current_node)

    def _log_traversal_completion(self, traversal_stats, elapsed_time, paths_found):
        """
        Log completion of graph traversal with performance metrics.

        Args:
            traversal_stats (dict): Dictionary containing traversal metrics
            elapsed_time (float): Total time taken for traversal in seconds
            paths_found (int): Number of paths found during traversal
        """
        # Log basic completion info
        logger.debug(
            f"Graph traversal completed: {elapsed_time:.3f}s, "
            f"nodes visited: {traversal_stats['nodes_visited']}, "
            f"max path length: {traversal_stats['max_path_length']}, "
            f"paths found: {paths_found}"
        )

        # Log warnings for potentially problematic traversals
        if elapsed_time > MAX_TRAVERSAL_TIME_SECONDS:
            logger.warning(
                f"Graph traversal completed but took excessive time: {elapsed_time:.2f}s. "
                f"This may indicate graph structure issues. "
                f"Start node: {traversal_stats['start_node']}, target: {traversal_stats['target_tag']}, "
                f"nodes visited: {traversal_stats['nodes_visited']}, paths found: {paths_found}"
            )

        if traversal_stats["nodes_visited"] > MAX_NODES_VISITED:
            logger.warning(
                f"Graph traversal visited {traversal_stats['nodes_visited']} nodes, "
                f"which exceeds the recommended threshold of {MAX_NODES_VISITED}. "
                f"Consider checking for cycles or optimizing graph structure."
            )

        if traversal_stats["max_path_length"] > MAX_PATH_LENGTH:
            logger.warning(
                f"Graph traversal encountered path length of {traversal_stats['max_path_length']} nodes, "
                f"which exceeds the recommended threshold of {MAX_PATH_LENGTH}. "
                f"This may indicate very deep dependencies or potential cycles."
            )

    def get_graph_health_info(self):
        """
        Get diagnostic information about the graph structure.

        Returns:
            dict: Dictionary containing graph health metrics
        """
        health_info = {
            "total_nodes": len(self.nodes()),
            "total_edges": len(self.edges()),
            "is_acyclic": True,
            "cycles_found": [],
            "max_degree": 0,
            "nodes_with_high_degree": [],
            "isolated_nodes": [],
        }

        try:
            # Check for cycles
            health_info["is_acyclic"] = nx.is_directed_acyclic_graph(self)
            if not health_info["is_acyclic"]:
                try:
                    health_info["cycles_found"] = list(nx.simple_cycles(self))
                    logger.warning(
                        f"Graph contains {len(health_info['cycles_found'])} cycles"
                    )
                except Exception as e:
                    logger.error(f"Error detecting cycles: {e}")

            # Check for nodes with unusually high degree (potential performance issues)
            degree_threshold = 50  # Configurable threshold
            for node in self.nodes():
                degree = self.degree(node)
                health_info["max_degree"] = max(health_info["max_degree"], degree)

                if degree > degree_threshold:
                    health_info["nodes_with_high_degree"].append((node, degree))

            # Check for isolated nodes
            health_info["isolated_nodes"] = list(nx.isolates(self))

            # Log warnings for potential issues
            if health_info["nodes_with_high_degree"]:
                logger.warning(
                    f"Found {len(health_info['nodes_with_high_degree'])} nodes with high degree (>{degree_threshold}). "
                    f"This may cause performance issues during traversal."
                )

            if len(health_info["isolated_nodes"]) > 0:
                logger.info(
                    f"Found {len(health_info['isolated_nodes'])} isolated nodes in graph"
                )

        except Exception as e:
            logger.error(f"Error during graph health check: {e}")

        return health_info

    def log_graph_health(self):
        """
        Log comprehensive graph health information.
        This can be called periodically or after graph construction to check for issues.
        """
        health_info = self.get_graph_health_info()

        logger.info(
            f"Graph health summary: {health_info['total_nodes']} nodes, "
            f"{health_info['total_edges']} edges, max degree: {health_info['max_degree']}, "
            f"acyclic: {health_info['is_acyclic']}"
        )

        if not health_info["is_acyclic"]:
            logger.error(
                f"Graph is not acyclic! Found {len(health_info['cycles_found'])} cycles"
            )

        if health_info["nodes_with_high_degree"]:
            logger.warning(
                f"High degree nodes detected: {health_info['nodes_with_high_degree'][:5]}"  # Show first 5
            )

    def add_tag(self, tag, nodes=None):
        """
        Add a tag to the graph and associate it with specified nodes.

        Parameters:
            tag (str): The tag to add.
            nodes (iterable, optional): An iterable of nodes to associate with the tag. Defaults to None.

        Returns:
            None
        """
        if tag not in self.tags:
            self.tags[tag] = set()
        if nodes:
            self.tags[tag].update(nodes)
            # Ensure that all nodes exist in the graph
            self.add_nodes_from(nodes)

    def remove_tag(self, tag):
        """
        Remove a tag and its associations from the graph.

        Parameters:
            tag (str): The tag to remove.

        Returns:
            None
        """
        if tag in self.tags:
            del self.tags[tag]

    def add_node(self, node, **attr):
        """
        Add a node to the TaggedGraph and associate it with its tags.

        Parameters:
            node: The node to add.
            **attr: Additional attributes for the node.

        Returns:
            None
        """
        super().add_node(node, **attr)
        tags = node.get_tags()
        for tag in tags:
            self.add_tag(tag, [node])

    def add_node_with_tags(self, node, tags=None, **attr):
        """
        Add a single node with associated tags to the graph.

        Parameters:
            node: The node to add.
            tags (iterable, optional): An iterable of tags to associate with the node. Defaults to None.
            **attr: Additional attributes for the node.

        Returns:
            None
        """
        super().add_node(node, **attr)
        if tags:
            for tag in tags:
                self.add_tag(tag, [node])

    def add_nodes_with_tags(self, nodes_with_tags, **attr):
        """
        Add multiple nodes with their associated tags to the graph.

        Parameters:
            nodes_with_tags (dict): A dictionary mapping nodes to an iterable of tags.
            **attr: Additional attributes for the nodes.

        Returns:
            None
        """
        for node, tags in nodes_with_tags.items():
            self.add_node_with_tags(node, tags, **attr)

    def remove_node(self, node):
        """
        Remove a node from the graph and dissociate it from all tags.

        Parameters:
            node: The node to remove.

        Returns:
            None
        """
        super().remove_node(node)
        for _, nodes in self.tags.items():
            nodes.discard(node)

    def get_nodes_by_tag(self, tag):
        """
        Retrieve all nodes associated with a given tag.

        Parameters:
            tag (str): The tag to query.

        Returns:
            set: A set of nodes associated with the tag. Returns an empty set if the tag does not exist.
        """
        return self.tags.get(tag, set())

    def get_nodes_for_tags(self, tags: list):
        """
        Retrieve all nodes associated with any of the specified tags.

        Parameters:
            tags (list): A list of tags to query.

        Returns:
            set: A set of nodes associated with the provided tags.
        """
        nodeset = set()

        for tag in tags:
            nodeset.update(self.get_nodes_by_tag(tag))

        return nodeset

    def get_tags_for_node(self, node):
        """
        Retrieve all tags associated with a given node.

        Parameters:
            node: The node to query.

        Returns:
            set: A set of tags associated with the node.
        """
        return {tag for tag, nodes in self.tags.items() if node in nodes}

    def add_tags_to_node(self, node, tags):
        """
        Add one or more tags to an existing node.

        Parameters:
            node: The node to tag.
            tags (iterable): An iterable of tags to associate with the node.

        Returns:
            None

        Raises:
            nx.NetworkXError: If the node is not present in the graph.
        """
        if node not in self:
            raise nx.NetworkXError(f"Node {node} is not in the graph.")
        for tag in tags:
            self.add_tag(tag, [node])

    def remove_tags_from_node(self, node, tags):
        """
        Remove one or more tags from a node.

        Parameters:
            node: The node from which to remove tags.
            tags (iterable): An iterable of tags to dissociate from the node.

        Returns:
            None
        """
        for tag in tags:
            if tag in self.tags:
                self.tags[tag].discard(node)
                # Remove the tag if no nodes are associated
                if not self.tags[tag]:
                    del self.tags[tag]
