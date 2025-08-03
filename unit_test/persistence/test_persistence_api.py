import pytest
from unittest.mock import AsyncMock
from gatox.github.api import Api


@pytest.fixture
def api():
    """Create an API instance for testing."""
    return Api("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


@pytest.mark.asyncio
async def test_invite_collaborator_success(api):
    """Test successful collaborator invitation API call."""
    api.call_put = AsyncMock()
    api.call_put.return_value.status_code = 201

    result = await api.invite_collaborator("test/repo", "username")

    assert result is True
    api.call_put.assert_called_once_with(
        "/repos/test/repo/collaborators/username", params={"permission": "admin"}
    )


@pytest.mark.asyncio
async def test_invite_collaborator_already_invited(api):
    """Test collaborator invitation when user is already invited."""
    api.call_put = AsyncMock()
    api.call_put.return_value.status_code = 204

    result = await api.invite_collaborator("test/repo", "username")

    assert result is True


@pytest.mark.asyncio
async def test_invite_collaborator_failure(api):
    """Test failed collaborator invitation."""
    api.call_put = AsyncMock()
    api.call_put.return_value.status_code = 403

    result = await api.invite_collaborator("test/repo", "username")

    assert result is False


@pytest.mark.asyncio
async def test_create_deploy_key_success(api):
    """Test successful deploy key creation."""
    api.call_post = AsyncMock()
    api.call_post.return_value.status_code = 201

    result = await api.create_deploy_key(
        "test/repo", "Test Key", "ssh-rsa AAAA...", read_only=False
    )

    assert result is True
    api.call_post.assert_called_once_with(
        "/repos/test/repo/keys",
        params={"title": "Test Key", "key": "ssh-rsa AAAA...", "read_only": False},
    )


@pytest.mark.asyncio
async def test_create_deploy_key_failure(api):
    """Test failed deploy key creation."""
    api.call_post = AsyncMock()
    api.call_post.return_value.status_code = 422

    result = await api.create_deploy_key("test/repo", "Test Key", "invalid-key")

    assert result is False


@pytest.mark.asyncio
async def test_create_workflow_on_branch_success(api):
    """Test successful workflow creation on branch."""
    from unittest.mock import MagicMock

    # Mock the repository info call
    api.get_repository = AsyncMock(return_value={"default_branch": "main"})

    # Mock the branch info call
    branch_response = MagicMock()
    branch_response.status_code = 200
    branch_response.json.return_value = {"object": {"sha": "abc123"}}

    # Mock the branch creation call
    create_branch_response = MagicMock()
    create_branch_response.status_code = 201

    # Mock the commit_file call
    api.commit_file = AsyncMock(return_value="def456")

    api.call_get = AsyncMock(return_value=branch_response)
    api.call_post = AsyncMock(return_value=create_branch_response)

    result = await api.create_workflow_on_branch(
        "test/repo", "feature-branch", "test.yml", "workflow content"
    )

    assert result == "def456"
    
    # Verify all expected calls were made
    api.get_repository.assert_called_once_with("test/repo")
    api.call_get.assert_called_once_with("/repos/test/repo/git/ref/heads/main")
    api.call_post.assert_called_once_with(
        "/repos/test/repo/git/refs", 
        params={"ref": "refs/heads/feature-branch", "sha": "abc123"}
    )
    api.commit_file.assert_called_once_with(
        repo_name="test/repo",
        branch_name="feature-branch", 
        file_path=".github/workflows/test.yml",
        file_content=b"workflow content",
        message="[skip ci] Workflow"
    )


@pytest.mark.asyncio
async def test_create_workflow_on_branch_repo_failure(api):
    """Test workflow creation failure due to repository access."""
    api.get_repository = AsyncMock(return_value=None)

    result = await api.create_workflow_on_branch(
        "test/repo", "feature-branch", "test.yml", "workflow content"
    )

    assert result is False
