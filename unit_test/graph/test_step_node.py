from gatox.workflow_graph.nodes.step import StepNode


def test_step_node_init_script():
    """Test initialization of StepNode with script type"""
    step_data = {"name": "test step", "run": "echo hello"}

    node = StepNode(
        step_data=step_data,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    assert node.name == "test/repo:main:.github/workflows/test.yml:build:test step_1"
    assert node.type == "script"
    assert not node.is_checkout
    assert not node.is_sink
    assert not node.metadata
    assert not node.hard_gate
    assert not node.soft_gate


def test_step_node_init_action():
    """Test initialization of StepNode with action type"""
    step_data = {
        "name": "checkout",
        "uses": "actions/checkout@v2",
        "with": {"ref": "${{ github.event.pull_request.head.ref }}"},
    }

    node = StepNode(
        step_data=step_data,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    assert node.type == "action"
    assert not node.is_checkout
    assert node.uses == "actions/checkout@v2"
    assert node.params == {"ref": "${{ github.event.pull_request.head.ref }}"}


def test_step_node_init_unknown():
    """Test initialization of StepNode with unknown type"""
    step_data = {"name": "unknown step"}

    node = StepNode(
        step_data=step_data,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    assert node.type == "unknown"


def test_step_node_get_tags():
    """Test get_tags method"""
    step_data = {"name": "test step", "run": "echo hello"}

    node = StepNode(
        step_data=step_data,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    tags = node.get_tags()
    assert "StepNode" in tags
    assert "checkout" not in tags
    assert "sink" not in tags
    assert "injectable" not in tags
    assert "permission_blocker" not in tags
    assert "permission_check" not in tags

    node.extra_tags.add("extra_tag")
    assert "extra_tag" in node.get_tags()


def test_step_node_get_attrs():
    """Test get_attrs method"""
    step_data = {"name": "test step", "run": "echo hello"}

    node = StepNode(
        step_data=step_data,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    attrs = node.get_attrs()
    assert attrs["StepNode"] is True
    assert attrs["type"] == "script"
    assert not attrs["is_soft_gate"]
    assert not attrs["is_hard_gate"]


def test_step_node_equality():
    """Test equality comparison"""
    step_data1 = {"name": "test step", "run": "echo hello"}

    step_data2 = {"name": "test step", "run": "echo world"}

    node1 = StepNode(
        step_data=step_data1,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    node2 = StepNode(
        step_data=step_data2,
        ref="main",
        repo_name="test/repo",
        workflow_path=".github/workflows/test.yml",
        job_name="build",
        step_number=1,
    )

    assert node1 == node2
    assert hash(node1) == hash(node2)
