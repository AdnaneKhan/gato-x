from gatox.workflow_graph.nodes.node import Node


def test_node_init():
    """Test Node initialization"""
    node = Node("test_node")
    assert node.name == "test_node"


def test_node_repr():
    """Test Node string representation"""
    node = Node("test_node")
    assert repr(node) == "Node('test_node')"


def test_node_hash():
    """Test Node hash function"""
    node1 = Node("test_node")
    node2 = Node("test_node")
    assert hash(node1) == hash(node2)
    assert hash(node1) == hash(("test_node", "Node"))


def test_node_equality():
    """Test Node equality comparison"""
    node1 = Node("test_node")
    node2 = Node("test_node")
    node3 = Node("different_node")

    assert node1 == node2
    assert node1 != node3
    assert node1 != "not_a_node"


def test_node_get_needs():
    """Test Node get_needs method"""
    node = Node("test_node")
    assert node.get_needs() == []


def test_node_get_tags():
    """Test Node get_tags method"""
    node = Node("test_node")
    assert node.get_tags() == {"Node"}


def test_node_extra_tags():
    """Test Node extra tags"""
    node = Node("test_node")
    node.extra_tags.add("extra_tag")
    assert node.get_tags() == {"Node", "extra_tag"}
