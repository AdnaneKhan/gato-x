import networkx as nx
from unittest.mock import AsyncMock, MagicMock
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


class MockNode:
    def __init__(self, name, needs=None, tags=None):
        self.name = name
        self._needs = needs or []
        self._tags = set(tags or [])

    def get_needs(self):
        return self._needs

    def get_tags(self):
        return self._tags

    def __repr__(self):
        return f"MockNode({self.name})"


def test_tagged_graph_init():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    assert graph.builder == builder
    assert isinstance(graph, nx.DiGraph)


def test_add_node():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A", tags=["tag1"])
    graph.add_node(node)
    assert node in graph
    assert "tag1" in graph.tags
    assert node in graph.tags["tag1"]


def test_add_tag():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A")
    graph.add_node(node)
    graph.add_tag("new_tag", [node])
    assert "new_tag" in graph.tags
    assert node in graph.tags["new_tag"]


def test_remove_tag():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A", tags=["tag1"])
    graph.add_node(node)
    graph.remove_tag("tag1")
    assert "tag1" not in graph.tags


def test_remove_node():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A", tags=["tag1", "tag2"])
    graph.add_node(node)
    graph.remove_node(node)
    assert node not in graph
    assert node not in graph.get_nodes_by_tag("tag1")
    assert node not in graph.get_nodes_by_tag("tag2")


def test_get_nodes_by_tag():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node1 = MockNode("A", tags=["tag1"])
    node2 = MockNode("B", tags=["tag2"])
    graph.add_node(node1)
    graph.add_node(node2)
    assert graph.get_nodes_by_tag("tag1") == {node1}
    assert graph.get_nodes_by_tag("tag2") == {node2}


def test_add_tags_to_node():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A", tags=["initial"])
    graph.add_node(node)
    graph.add_tags_to_node(node, ["extra"])
    assert "extra" in graph.tags
    assert node in graph.tags["extra"]


def test_remove_tags_from_node():
    builder = MagicMock()
    graph = TaggedGraph(builder=builder)
    node = MockNode("A", tags=["tag1", "tag2"])
    graph.add_node(node)
    graph.remove_tags_from_node(node, ["tag1"])
    assert "tag1" not in graph.get_tags_for_node(node)
    assert "tag2" in graph.get_tags_for_node(node)


async def test_dfs_to_tag():
    builder = MagicMock()
    builder.initialize_node = MagicMock()
    graph = TaggedGraph(builder=builder)

    nodeA = MockNode("A", needs=[], tags=["start"])
    nodeB = MockNode("B", needs=[nodeA], tags=["middle"])
    nodeC = MockNode("C", needs=[nodeB], tags=["target"])
    graph.add_node(nodeA)
    graph.add_node(nodeB)
    graph.add_node(nodeC)
    graph.add_edge(nodeA, nodeB)
    graph.add_edge(nodeB, nodeC)

    paths = await graph.dfs_to_tag(nodeA, "target", api=AsyncMock())
    assert len(paths) == 1
    assert paths[0] == [nodeA, nodeB, nodeC]
