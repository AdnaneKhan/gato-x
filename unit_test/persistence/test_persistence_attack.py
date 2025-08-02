import pytest
from unittest.mock import patch, AsyncMock
from gatox.attack.persistence.persistence_attack import PersistenceAttack


@pytest.fixture
def persistence_attacker():
    """Create a persistence attacker instance for testing."""
    return PersistenceAttack("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_invite_collaborators_success(mock_output, persistence_attacker):
    """Test successful collaborator invitation."""
    # Mock the setup and API calls
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.invite_collaborator = AsyncMock(return_value=True)

    result = await persistence_attacker.invite_collaborators(
        "test/repo", ["user1", "user2"]
    )

    assert result is True
    assert persistence_attacker.api.invite_collaborator.call_count == 2


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_invite_collaborators_partial_success(mock_output, persistence_attacker):
    """Test partial success in collaborator invitation."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    
    # Mock first invite success, second failure
    persistence_attacker.api.invite_collaborator = AsyncMock(
        side_effect=[True, False]
    )

    result = await persistence_attacker.invite_collaborators(
        "test/repo", ["user1", "user2"]
    )

    assert result is True  # Should still return True if at least one succeeds


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_invite_collaborators_setup_failure(mock_output, persistence_attacker):
    """Test failure due to setup issues."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=False)

    result = await persistence_attacker.invite_collaborators(
        "test/repo", ["user1"]
    )

    assert result is False


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_deploy_key_success(mock_output, persistence_attacker):
    """Test successful deploy key creation."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_deploy_key = AsyncMock(return_value=True)

    result = await persistence_attacker.create_deploy_key("test/repo")

    assert result is True
    persistence_attacker.api.create_deploy_key.assert_called_once()


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_deploy_key_failure(mock_output, persistence_attacker):
    """Test deploy key creation failure."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_deploy_key = AsyncMock(return_value=False)

    result = await persistence_attacker.create_deploy_key("test/repo")

    assert result is False


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_pwn_request_workflow_success(mock_output, persistence_attacker):
    """Test successful pwn request workflow creation."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_workflow_on_branch = AsyncMock(return_value=True)

    result = await persistence_attacker.create_pwn_request_workflow("test/repo")

    assert result is True
    persistence_attacker.api.create_workflow_on_branch.assert_called_once()


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_pwn_request_workflow_custom_branch(mock_output, persistence_attacker):
    """Test pwn request workflow creation with custom branch."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_workflow_on_branch = AsyncMock(return_value=True)

    result = await persistence_attacker.create_pwn_request_workflow(
        "test/repo", "custom-branch"
    )

    assert result is True
    # Verify the correct branch name was passed
    call_args = persistence_attacker.api.create_workflow_on_branch.call_args
    assert call_args[0][1] == "custom-branch"  # Second argument is branch name