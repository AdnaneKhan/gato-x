from unittest.mock import MagicMock

from gatox.caching.cache_manager import CacheManager


def test_init_cache():
    """ """
    cache = CacheManager()
    assert cache.workflow_cache == {}


def test_set_workflow():
    """Test setting and retrieving a workflow from the cache."""
    cache = CacheManager()

    mock_wf = MagicMock()

    cache.set_workflow("testOrg/testRepo1", "test.yml", mock_wf)

    assert cache.get_workflow("testOrg/testRepo1", "test.yml") == mock_wf


def test_set_double_workflow():
    """Test setting a workflow twice - this should return the most recent workflow."""
    cache = CacheManager()

    mock_wf = MagicMock()
    mock_wf2 = MagicMock()

    cache.set_workflow("testOrg/testRepo2", "test.yml", mock_wf)
    cache.set_workflow("testOrg/testRepo2", "test.yml", mock_wf2)

    assert cache.get_workflow("testOrg/testRepo2", "test.yml") == mock_wf2


def test_set_empty_and_cached():
    """Test if setting the repo"""
    CacheManager().set_empty("testOrg/testRepoEmpty")

    assert CacheManager().is_repo_cached("testOrg/testRepoEmpty")


def test_get_workflows():
    """Test getting all workflows for a repository."""

    cache = CacheManager()

    mock_wf = MagicMock()
    mock_wf2 = MagicMock()

    cache.set_workflow("testOrg/testRepo3", "test.yml", mock_wf)
    cache.set_workflow("testOrg/testRepo3", "test2.yml", mock_wf2)
    wf_set = cache.get_workflows("testOrg/testRepo3")

    assert mock_wf in wf_set
    assert mock_wf2 in wf_set


def test_get_workflows_fail():
    """Test getting all workflows for a repository."""

    cache = CacheManager()

    mock_wf = MagicMock()
    mock_wf2 = MagicMock()

    cache.set_workflow("testOrg/testRepo3", "test.yml", mock_wf)
    cache.set_workflow("testOrg/testRepo3", "test2.yml", mock_wf2)
    assert cache.get_workflows("testOrg/testRepoNone") == set()


def test_set_get_repository():
    """Test setting and getting a repository to the cache."""
    cache = CacheManager()

    mock_repo = MagicMock()
    mock_repo.name = "testOrg/testRepo"

    cache.set_repository(mock_repo)

    assert cache.get_repository("testOrg/testRepo") == mock_repo


def test_get_set_repository_fail():
    """Test failure case when repository does not exist"""
    cache = CacheManager()

    mock_repo = MagicMock()
    mock_repo.name = "testOrg/testRepo"

    cache.set_repository(mock_repo)

    assert cache.get_repository("badOrg/BadRepo") is None


def test_set_get_action():
    """Test setting and getting a reusable action."""
    cache = CacheManager()

    mock_action = "someActionContentsHere"

    cache.set_action(
        "testOrg/testRepo", ".github/actions/action.yml", "main", mock_action
    )

    assert (
        cache.get_action("testOrg/testRepo", ".github/actions/action.yml", "main")
        == mock_action
    )
