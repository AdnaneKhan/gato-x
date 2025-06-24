import os
import pathlib
import pytest
import json

from unittest.mock import patch, AsyncMock
from gatox.github.api import Api

from gatox.models.workflow import Workflow
from gatox.enumerate.enumerate import Enumerator
from gatox.cli.output import Output
from gatox.caching.cache_manager import CacheManager

from unit_test.utils import escape_ansi as escape_ansi

TEST_REPO_DATA = None
TEST_WORKFLOW_YML = None
TEST_ORG_DATA = None

Output(True)

BASE_MOCK_RUNNER = [
    {
        "machine_name": "unittest1",
        "runner_name": "much_unit_such_test",
        "runner_type": "organization",
        "non_ephemeral": False,
        "token_permissions": {"Actions": "write"},
        "runner_group": "Default",
        "requested_labels": ["self-hosted", "Linux", "X64"],
    }
]


@pytest.fixture(autouse=True)
def clear_cache():
    """
    Fixture to clear the CacheManager singleton instance before each test
    to prevent test interference.
    """
    CacheManager._instance = None
    yield
    # Clean up after test as well
    CacheManager._instance = None


@pytest.fixture(scope="session", autouse=True)
def load_test_files(request):
    global TEST_REPO_DATA
    global TEST_ORG_DATA
    global TEST_WORKFLOW_YML
    curr_path = pathlib.Path(__file__).parent.resolve()
    test_repo_path = os.path.join(curr_path, "files/example_repo.json")
    test_org_path = os.path.join(curr_path, "files/example_org.json")
    test_wf_path = os.path.join(curr_path, "files/main.yaml")

    with open(test_repo_path, "r") as repo_data:
        TEST_REPO_DATA = json.load(repo_data)

    with open(test_org_path, "r") as repo_data:
        TEST_ORG_DATA = json.load(repo_data)

    with open(test_wf_path, "r") as wf_data:
        TEST_WORKFLOW_YML = wf_data.read()


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
def test_init(mock_api):
    """Test constructor for enumerator."""

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_log=False,
    )

    assert gh_enumeration_runner.http_proxy == "localhost:8080"


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_self_enumerate(mock_api, capsys):
    """Test constructor for enumerator."""

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.check_organizations.return_value = []

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_log=False,
    )

    await gh_enumeration_runner.self_enumeration()

    captured = capsys.readouterr()

    print_output = captured.out
    assert "The user testUser belongs to 0 organizations!" in escape_ansi(print_output)


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_repo_admin(mock_api, capsys):
    """Test constructor for enumerator."""

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_log=False,
    )

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.retrieve_run_logs.return_value = BASE_MOCK_RUNNER

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    repo_data["permissions"]["admin"] = True

    mock_api.return_value.get_repository.return_value = repo_data

    await gh_enumeration_runner.enumerate_repo(repo_data["full_name"])

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The user is an administrator on the" in escape_ansi(print_output)


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_repo_admin_no_wf(mock_api, capsys):
    """Test constructor for enumerator."""

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
        skip_log=False,
    )

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo"],
    }

    mock_api.return_value.retrieve_run_logs.return_value = BASE_MOCK_RUNNER

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    repo_data["permissions"]["admin"] = True

    mock_api.return_value.get_repository.return_value = repo_data

    await gh_enumeration_runner.enumerate_repo(repo_data["full_name"])

    captured = capsys.readouterr()

    print_output = captured.out

    assert " is public this token can be used to approve a" in escape_ansi(print_output)


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_validate(mock_api, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.check_organizations.return_value = []

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.validate_only()
    out, err = capfd.readouterr()
    assert "authenticated user is: testUser" in escape_ansi(out)
    assert "The user testUser belongs to 0 organizations!" in escape_ansi(out)


@patch("gatox.enumerate.ingest.ingest.asyncio.sleep")
@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_repo(mock_api, mock_time, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.enumerate_repo("octocat/Hello-World")
    out, err = capfd.readouterr()
    assert "Checking repository: octocat/Hello-World" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_called_once_with("octocat/Hello-World")


@patch("gatox.enumerate.ingest.ingest.asyncio.sleep")
@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_org(mock_api, mock_time, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow", "admin:org"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA
    mock_api.return_value.get_organization_details.return_value = TEST_ORG_DATA

    mock_api.return_value.get_org_secrets.return_value = [
        {
            "name": "DEPLOY_TOKEN",
            "created_at": "2019-08-10T14:59:22Z",
            "updated_at": "2020-01-10T14:59:22Z",
            "visibility": "all",
        },
        {
            "name": "GH_TOKEN",
            "created_at": "2019-08-10T14:59:22Z",
            "updated_at": "2020-01-10T14:59:22Z",
            "visibility": "selected",
            "selected_repositories_url": "https://api.github.com/orgs/testOrg/actions/secrets/GH_TOKEN/repositories",
        },
    ]

    mock_api.return_value.check_org_runners.return_value = {
        "total_count": 1,
        "runners": [
            {
                "id": 21,
                "name": "ghrunner-test",
                "os": "Linux",
                "status": "online",
                "busy": False,
                "labels": [
                    {"id": 1, "name": "self-hosted", "type": "read-only"},
                    {"id": 2, "name": "Linux", "type": "read-only"},
                    {"id": 3, "name": "X64", "type": "read-only"},
                ],
            }
        ],
    }

    mock_api.return_value.check_org_repos.side_effect = [[TEST_REPO_DATA], [], []]

    mock_api.return_value.get_secrets.return_value = [
        {
            "name": "TEST_SECRET",
            "created_at": "2019-08-10T14:59:22Z",
            "updated_at": "2020-01-10T14:59:22Z",
        }
    ]

    mock_api.return_value.get_repo_org_secrets.return_value = []

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.enumerate_organization("github")

    out, err = capfd.readouterr()

    escaped_output = escape_ansi(out)

    assert "The organization has 2 secret(s)" in escaped_output
    assert "organization has 1 org-level self-hosted runners" in escaped_output
    assert "DEPLOY_TOKEN" in escaped_output
    assert "ghrunner-test" in escaped_output


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_repo_runner(mock_api, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.get_repo_runners.return_value = [
        {
            "id": 2,
            "name": "17e749a1b008",
            "os": "Linux",
            "status": "offline",
            "busy": False,
            "labels": [
                {"id": 1, "name": "self-hosted", "type": "read-only"},
                {
                    "id": 2,
                    "name": "Linux",
                    "type": "read-only",
                },
                {
                    "id": 3,
                    "name": "X64",
                    "type": "read-only",
                },
            ],
        }
    ]

    test_repodata = TEST_REPO_DATA.copy()

    test_repodata["permissions"]["admin"] = True

    mock_api.return_value.get_repository.return_value = test_repodata

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.enumerate_repo("octocat/Hello-World")
    out, err = capfd.readouterr()

    escaped_output = escape_ansi(out)

    assert "The repository has 1 repo-level self-hosted runners!" in escaped_output

    assert "[!] The user is an administrator on the repository!" in escaped_output

    assert "Labels: self-hosted, Linux, X64" in escaped_output


@patch("gatox.enumerate.ingest.ingest.asyncio.sleep")
@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_repos(mock_api, mock_time, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.enumerate_repos(["octocat/Hello-World"])
    out, _ = capfd.readouterr()
    assert "Checking repository: octocat/Hello-World" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_called_once_with("octocat/Hello-World")


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_repos_empty(mock_api, capfd):
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.get_repository.return_value = TEST_REPO_DATA

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    await gh_enumeration_runner.enumerate_repos([])
    out, _ = capfd.readouterr()
    assert "The list of repositories was empty!" in escape_ansi(out)
    mock_api.return_value.get_repository.assert_not_called()


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_bad_token(mock_api):
    gh_enumeration_runner = Enumerator(
        "ghp_BADTOKEN",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    mock_api.return_value.is_app_token.return_value = False

    mock_api.return_value.check_user.return_value = None

    val = await gh_enumeration_runner.self_enumeration()

    assert val is False


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_unscoped_token(mock_api, capfd):
    gh_enumeration_runner = Enumerator(
        "ghp_BADTOKEN",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    mock_api.return_value.is_app_token.return_value = False
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["public_repo"],
    }

    status = await gh_enumeration_runner.self_enumeration()

    out, _ = capfd.readouterr()
    assert "Self-enumeration requires the repo scope!" in escape_ansi(out)
    assert status is False


@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enum_self_no_repos(mock_api, capfd):
    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
        output_json="test.json",
    )

    mock_api.return_value.is_app_token.return_value = False
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo"],
    }

    orgs, repos = await gh_enumeration_runner.self_enumeration()

    assert orgs == []
    assert repos == []

    out, _ = capfd.readouterr()


@patch(
    "gatox.enumerate.enumerate.WorkflowGraphBuilder.build_graph_from_yaml",
    new_callable=AsyncMock,
)
@patch("gatox.enumerate.enumerate.Enumerator.process_graph", new_callable=AsyncMock)
@patch(
    "gatox.enumerate.repository.RepositoryEnum.enumerate_repository",
    new_callable=AsyncMock,
)
@patch("gatox.enumerate.enumerate.Api", return_value=AsyncMock(Api))
async def test_enumerate_commit(mock_api, mock_enum_repo, mock_pg, mock_build):
    """Test commit enumeration functionality."""

    # Set up the mocks before creating the Enumerator
    mock_api.return_value.is_app_token.return_value = False
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "scopes": ["repo", "workflow"],
    }

    repo_data = json.loads(json.dumps(TEST_REPO_DATA))
    mock_api.return_value.get_repository.return_value = repo_data
    mock_api.return_value.retrieve_workflow_ymls_ref.return_value = [
        Workflow(repo_data["full_name"], TEST_WORKFLOW_YML, "main.yaml")
    ]

    gh_enumeration_runner = Enumerator(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy=None,
        skip_log=True,
    )

    sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    repo = await gh_enumeration_runner.enumerate_commit(repo_data["full_name"], sha)

    mock_api.return_value.retrieve_workflow_ymls_ref.assert_called_once_with(
        repo_data["full_name"], sha
    )
    mock_build.assert_awaited()
    assert repo.name == repo_data["full_name"]
