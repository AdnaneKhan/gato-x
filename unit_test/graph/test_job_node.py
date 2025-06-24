from gatox.workflow_graph.nodes.job import JobNode


def test_job_node_init():
    """Test JobNode initialization"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    assert job.name == "org/repo:main:.github/workflows/test.yml:test_job"
    assert job.ref == "main"
    assert job.repo_name() == "org/repo"
    assert job.params == {}
    assert job.if_condition is None
    assert job.wf_reference is None
    assert job.needs == []
    assert job.deployments == []
    assert job.self_hosted is False
    assert job.outputs == {}


def test_job_node_hash():
    """Test JobNode hash"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")
    assert hash(job) == hash((job.name, "JobNode"))


def test_check_selfhosted():
    """Test self-hosted runner detection"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    # Test direct self-hosted label
    assert job._check_selfhosted({"runs-on": "self-hosted"}) is True

    # Test non self-hosted runner
    assert job._check_selfhosted({"runs-on": "ubuntu-latest"}) is False


def test_get_workflow_name():
    """Test getting workflow name"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")
    assert job.get_workflow_name() == "test.yml"


def test_populate():
    """Test populating job node with definition"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    job_def = {
        "runs-on": "self-hosted",
        "with": {"param1": "value1"},
        "environment": "prod",
        "env": {"ENV_VAR": "value"},
        "outputs": {"output1": "value1"},
    }

    job.populate(job_def, None)

    assert job.self_hosted is True
    assert job.params == {"param1": "value1"}
    assert job.deployments == ["prod"]
    assert job.get_env_vars() == {"ENV_VAR": "value"}
    assert job.outputs == {"output1": "value1"}


def test_job_node_equality():
    """Test JobNode equality comparison"""
    job1 = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")
    job2 = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")
    job3 = JobNode("other_job", "main", "org/repo", ".github/workflows/test.yml")

    assert job1 == job2
    assert job1 != job3


def test_get_needs():
    """Test getting job needs"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    need = JobNode("need_job", "main", "org/repo", ".github/workflows/test.yml")
    job.add_needs(need)

    assert job.get_needs() == [need]


def test_get_tags():
    """Test getting job tags"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    # Default tags
    assert job.get_tags() == {"JobNode"}

    # With self-hosted runner
    job.self_hosted = True
    assert job.get_tags() == {"JobNode", "self-hosted"}


def test_get_attrs():
    """Test getting job attributes"""
    job = JobNode("test_job", "main", "org/repo", ".github/workflows/test.yml")

    expected = {"JobNode": True, "is_soft_gate": False, "is_hard_gate": False}

    assert job.get_attrs() == expected
