from unittest.mock import AsyncMock, mock_open, patch

import pytest

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
        "test/repo", ["user1", "user2"], "push"
    )

    assert result is True
    assert persistence_attacker.api.invite_collaborator.call_count == 2


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_invite_collaborators_partial_success(mock_output, persistence_attacker):
    """Test partial success in collaborator invitation."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)

    # Mock first invite success, second failure
    persistence_attacker.api.invite_collaborator = AsyncMock(side_effect=[True, False])

    result = await persistence_attacker.invite_collaborators(
        "test/repo", ["user1", "user2"], "push"
    )

    assert result is True  # Should still return True if at least one succeeds


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_invite_collaborators_setup_failure(mock_output, persistence_attacker):
    """Test failure due to setup issues."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=False)

    result = await persistence_attacker.invite_collaborators(
        "test/repo", ["user1"], "push"
    )

    assert result is False


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
@patch("builtins.open", mock_open())
async def test_create_deploy_key_success(mock_output, persistence_attacker):
    """Test successful deploy key creation."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_deploy_key = AsyncMock(return_value=True)

    result = await persistence_attacker.create_deploy_key(
        "test/repo", "Test Key", "/tmp/test_key.pem"
    )

    assert result is True
    persistence_attacker.api.create_deploy_key.assert_called_once()


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_deploy_key_failure(mock_output, persistence_attacker):
    """Test deploy key creation failure."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)
    persistence_attacker.api.create_deploy_key = AsyncMock(return_value=False)

    result = await persistence_attacker.create_deploy_key(
        "test/repo", "Test Key", "/tmp/test_key.pem"
    )

    assert result is False


@pytest.mark.asyncio
@patch("gatox.attack.persistence.persistence_attack.Output")
async def test_create_deploy_key_no_path(mock_output, persistence_attacker):
    """Test deploy key creation failure when no key path is provided."""
    persistence_attacker.setup_user_info = AsyncMock(return_value=True)

    result = await persistence_attacker.create_deploy_key("test/repo", "Test Key", None)

    assert result is False
    mock_output.error.assert_called_with("Key path is required for deploy key creation")
