from gatox.workflow_graph.nodes.action import ActionNode


def test_init_basic():
    """Test basic initialization of ActionNode"""
    node = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node.name == "test/repo:main:.:actions/checkout@v2"
    assert not node.is_sink
    assert not node.is_checkout
    assert node.if_condition == ""
    assert not node.is_gate
    assert not node.hard_gate
    assert not node.metadata
    assert node.initialized
    assert node.caller_ref == "main"
    assert node.type == "UNK"


def test_init_known_gate():
    """Test initialization with known gate action"""
    node = ActionNode(
        action_name="actions-cool/check-user-permission@v1",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node.is_gate
    assert not node.hard_gate
    assert node.initialized


def test_init_known_hard_gate():
    """Test initialization with known hard gate action"""
    node = ActionNode(
        action_name="dependabot/fetch-metadata@v1",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node.is_gate
    assert node.hard_gate
    assert node.initialized


def test_init_known_good():
    """Test initialization with known good action"""
    node = ActionNode(
        action_name="azure/login@v1",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node.initialized


def test_init_docker():
    """Test initialization with docker action"""
    node = ActionNode(
        action_name="docker://alpine:latest",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node.initialized


def test_hash():
    """Test hash functionality"""
    node1 = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )
    node2 = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert hash(node1) == hash(node2)


def test_eq():
    """Test equality comparison"""
    node1 = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )
    node2 = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    assert node1 == node2


def test_get_tags():
    """Test getting tags"""
    node = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )
    node.is_checkout = True
    node.is_sink = True
    node.initialized = False
    node.is_gate = True

    tags = node.get_tags()
    assert "ActionNode" in tags
    assert "checkout" in tags
    assert "sink" in tags
    assert "uninitialized" in tags
    assert "permission_check" in tags


def test_get_attrs():
    """Test getting attributes"""
    node = ActionNode(
        action_name="actions/checkout@v2",
        ref="main",
        action_path=".",
        repo_name="test/repo",
        params={},
    )

    attrs = node.get_attrs()
    assert attrs["ActionNode"] is True
    assert attrs["type"] == "UNK"
    assert attrs["is_soft_gate"] is False
    assert attrs["is_hard_gate"] is False
