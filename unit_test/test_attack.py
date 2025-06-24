import re

from unittest.mock import patch
from unittest.mock import AsyncMock
from gatox.attack.attack import Attacker
from gatox.github.api import Api


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


def test_init():
    """Test constructor for enumerator."""

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    assert gh_attacker.http_proxy == "localhost:8080"


# @patch("gatox.attack.attack.time.sleep")
# @patch("gatox.attack.attack.Api")
# @patch("gatox.attack.attack.Git")
# def test_fork_pr(mock_git, mock_api, mock_time, capsys):
#     """Test creating a malicious fork PR
#     """

#     mock_api.return_value.check_user.return_value = {
#         "user": 'testUser',
#         "name": 'test user',
#         "scopes": ['repo','workflow']
#     }

#     mock_api.return_value.get_recent_workflow.return_value = \
#         12345

#     mock_api.return_value.fork_repository.return_value = \
#         'testOrg/targetRepo'
#     mock_api.return_value.create_fork_pr.return_value = \
#         'https://github.com/testOrg/targetRepo/pulls/12'

#     mock_api.return_value.proxies = {
#         "https": "http://localhost:8080"
#     }

#     gh_attacker = Attacker(

#         "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
#         socks_proxy=None,
#         http_proxy="localhost:8080"
#     )

#     gh_attacker.fork_pr_attack('targetRepo', 'develop', 'Bad PR', 'attack',
#                                'whoami', None, 'message')

#     captured = capsys.readouterr()

#     print_output = captured.out

#     assert "Successfully created fork: testOrg/targetRepo" in escape_ansi(
#         print_output
#     )

#     assert " viewed at: https://github.com/testOrg/targetRepo/pulls/12" in \
#         escape_ansi(print_output)

# @patch("gatox.attack.attack.time.sleep")
# @patch("gatox.attack.attack.Api")
# @patch("gatox.attack.attack.Git")
# def test_fork_pr_timeout(mock_git, mock_api, mock_time, capsys):
#     """Test creating a malicious fork PR
#     """

#     mock_api.return_value.check_user.return_value = {
#         "user": 'testUser',
#         "name": 'test user',
#         "scopes": ['repo','workflow']
#     }

#     mock_api.return_value.fork_repository.return_value = \
#         'testOrg/targetRepo'

#     mock_api.return_value.get_repository.return_value = \
#         None

#     mock_api.return_value.proxies = {
#         "https": "http://localhost:8080"
#     }

#     gh_attacker = Attacker(

#         "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
#         socks_proxy=None,
#         http_proxy="localhost:8080"
#     )

#     status = gh_attacker.fork_pr_attack(
#         'targetRepo', 'develop', 'Bad PR',
#         'attack', 'whoami', None, 'message'
#     )

#     captured = capsys.readouterr()

#     print_output = captured.out

#     assert status is False
#     assert "Forked repository not found after 30 seconds!" in escape_ansi(
#         print_output
#     )

# @patch("gatox.attack.attack.Api")
# @patch("gatox.attack.attack.Git")
# def test_fork_pr_perm(mock_git, mock_api, capsys):
#     """Test creating a malicious fork PR
#     """

#     mock_api.return_value.check_user.return_value = {
#         "user": 'testUser',
#         "name": 'test user',
#         "scopes": ['repo']
#     }

#     mock_api.return_value.proxies = {
#         "https": "http://localhost:8080"
#     }

#     gh_attacker = Attacker(

#         "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
#         socks_proxy=None,
#         http_proxy="localhost:8080"
#     )

#     gh_attacker.fork_pr_attack('targetRepo', 'develop', 'Bad PR', 'attack',
#                                'whoami', None, 'message')

#     captured = capsys.readouterr()

#     print_output = captured.out

#     assert " The user does not have the necessary scopes" in \
#         escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = (
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    )
    mock_api.return_value.get_recent_workflow.return_value = 1
    mock_api.return_value.get_workflow_status.return_value = 1
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Workflow logs downloaded to" in escape_ansi(print_output)
    assert "Workflow still incomplete but hit timeout!" not in escape_ansi(print_output)


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_perm(mock_api, capsys):
    """Test executing shell workflow attack with invalid permissions."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", False
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert " The user does not have the necessary scopes" in escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_fail_wf(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = (
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    )
    mock_api.return_value.get_recent_workflow.return_value = -1
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to find the created workflow!" in escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_fail_timeout(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = (
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    )
    mock_api.return_value.get_recent_workflow.return_value = 0
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to find the created workflow!" in escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_fail_timeout2(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.create_branch.return_value = True
    mock_api.return_value.commit_file.return_value = (
        "8933f8abb60e4e02ae1b8dd3f109bc7b6812e54f"
    )
    mock_api.return_value.get_recent_workflow.return_value = 1
    mock_api.return_value.get_workflow_status.return_value = 0
    mock_api.return_value.delete_branch.return_value = True

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The workflow is incomplete but hit the timeout" in escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_fail_branch(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.get_repo_branch.return_value = -1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Failed to check for remote branch!" in escape_ansi(print_output)


@patch("gatox.attack.attack.asyncio.sleep")
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_push_workflow_attack_fail_branch2(mock_api, mock_time, capsys):
    """Test the shell workflow attack."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.proxies = {"https": "http://localhost:8080"}

    mock_api.return_value.get_repo_branch.return_value = 1

    gh_attacker = Attacker(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.push_workflow_attack(
        "targetRepo", "whoami", None, None, "message", True
    )

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Remote branch, " in escape_ansi(print_output)
    assert ", already exists!" in escape_ansi(print_output)
