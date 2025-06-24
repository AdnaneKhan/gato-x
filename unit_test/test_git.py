import pathlib
import os
import pytest

from unittest.mock import MagicMock, patch
from gatox.git.git import Git
from gatox.git.utils import version_check, path_check, sed_check


@patch("gatox.git.utils.subprocess.run")
def test_check_git(mock_run):
    """Test test that the git version check works."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(**{"stdout": "git version 2.38.2\n", "returncode": 0})

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status == "2.38.2"


@patch("gatox.git.utils.subprocess.run")
def test_check_git_fail(mock_run):
    """Test failure case of git version check."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(
        **{"stdout": "command not found: git\n", "returncode": 1}
    )

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status is False


@patch("gatox.git.utils.subprocess.run")
def test_check_git_malformed(mock_run):
    """Test failure case of git version check."""

    mock_stdout = MagicMock()
    mock_stdout.configure_mock(**{"stdout": "git bad!\n", "returncode": 0})

    mock_run.return_value = mock_stdout

    git_status = version_check()
    mock_run.assert_called_once()

    assert git_status is False


@patch("gatox.git.utils.shutil.which")
def test_git_path_check(mock_run):
    """Test checking whether git exists on the path."""

    mock_run.return_value = "/usr/local/bin/git"

    exists = path_check()
    mock_run.assert_called_once()

    assert exists == "/usr/local/bin/git"


@patch("gatox.git.utils.shutil.which")
def test_sed_check(mock_run):
    """Test checking whether sed exists on the path."""
    mock_run.return_value = "/usr/bin/sed"

    exists = sed_check()
    mock_run.assert_called_once()

    assert exists == "/usr/bin/sed"


@patch("gatox.git.utils.shutil.which")
def test_git_path_not_found(mock_run):
    """Test case where git is not on path."""
    mock_run.return_value = None

    exists = path_check()
    mock_run.assert_called_once()

    assert exists is None


def test_constructor():
    """Tests the constructor for the git class."""
    with pytest.raises(ValueError):
        Git(
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "RepoOnly",
            proxies={"http": "http://proxy", "https": "https://proxy"},
        )


async def test_extract_workflows():
    """Tests extracting workflows from the '.github' folder."""
    curr_path = pathlib.Path(__file__).parent.resolve()

    git = Git("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "dummy/workflow_test")

    test_repo_path = os.path.join(curr_path, "files/workflow_test")
    ymls = await git.extract_workflow_ymls(repo_path=test_repo_path)

    assert len(ymls) == 1
