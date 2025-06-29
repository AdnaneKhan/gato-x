from unittest.mock import patch
from unittest.mock import MagicMock
from gatox.workflow_parser.utility import (
    decompose_action_ref,
    parse_github_path,
    check_sinks,
    parse_script,
    starts_with_any,
    process_matrix,
    getTokens,
    check_sus,
    checkUnsafe,
    process_runner,
)


def test_get_tokens_empty():
    assert getTokens("") == []


def test_get_tokens_no_context():
    assert getTokens("plain text") == []


def test_get_tokens_single_context():
    assert getTokens("${{ github.token }}") == ["github.token"]


def test_get_tokens_multiple_contexts():
    result = getTokens("${{ github.token }} ${{ github.actor }}")
    assert "github.token" in result
    assert "github.actor" in result


def test_get_tokens_with_or():
    result = getTokens("${{ github.token || github.actor }}")
    assert "github.token" in result
    assert "github.actor" in result


def test_starts_with_any_empty():
    assert not starts_with_any("", ["test"])


def test_starts_with_any_no_match():
    assert not starts_with_any("test", ["xyz", "abc"])


def test_starts_with_any_single_match():
    assert starts_with_any("test123", ["test"])


def test_starts_with_any_multiple_matches():
    assert starts_with_any("test123", ["xyz", "test", "abc"])


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_process_matrix_no_key(mock_config):
    job_def = {"strategy": {"matrix": {}}}
    runs_on = "${{ matrix.os }}"
    assert not process_matrix(job_def, runs_on)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_process_matrix_with_key(mock_config):
    mock_config().WORKFLOW_PARSING = {"GITHUB_HOSTED_LABELS": ["ubuntu-latest"]}
    job_def = {"strategy": {"matrix": {"os": ["self-hosted"]}}}
    runs_on = "${{ matrix.os }}"
    assert process_matrix(job_def, runs_on)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_process_matrix_includes(mock_config):
    mock_config().WORKFLOW_PARSING = {"GITHUB_HOSTED_LABELS": ["ubuntu-latest"]}
    job_def = {"strategy": {"matrix": {"include": [{"os": "self-hosted"}]}}}
    runs_on = "${{ matrix.os }}"
    assert process_matrix(job_def, runs_on)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_process_matrix_invalid(mock_config):
    job_def = {"strategy": "invalid"}
    runs_on = "${{ matrix.os }}"
    assert not process_matrix(job_def, runs_on)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
@patch("gatox.workflow_parser.utility.pattern")
@patch("gatox.workflow_parser.utility.check_sinks")
def test_parse_script_empty(mock_check_sinks, mock_pattern, mock_config):
    mock_check_sinks.return_value = False
    result = parse_script("")
    assert result == {
        "is_checkout": False,
        "metadata": None,
        "is_sink": False,
        "hard_gate": False,
        "soft_gate": False,
    }


@patch("gatox.workflow_parser.utility.ConfigurationManager")
@patch("gatox.workflow_parser.utility.pattern")
@patch("gatox.workflow_parser.utility.check_sinks")
def test_parse_script_checkout(mock_check_sinks, mock_pattern, mock_config):
    mock_check_sinks.return_value = False
    mock_pattern.search.return_value = MagicMock(
        group=lambda x: "prBranch" if x == 2 else ""
    )
    mock_config().WORKFLOW_PARSING = {"PR_ISH_VALUES": ["pr", "pull_request"]}

    script = "git checkout prBranch"
    result = parse_script(script)
    assert result["is_checkout"] is True
    assert result["metadata"] == "prBranch"


@patch("gatox.workflow_parser.utility.ConfigurationManager")
@patch("gatox.workflow_parser.utility.pattern")
@patch("gatox.workflow_parser.utility.check_sinks")
def test_parse_script_gates_and_sinks(mock_check_sinks, mock_pattern, mock_config):
    mock_check_sinks.return_value = True
    mock_config().WORKFLOW_PARSING = {"PR_ISH_VALUES": []}
    mock_pattern.search.return_value = None

    script = (
        "some commands\n"
        "isCrossRepository is set, use GITHUB_OUTPUT\n"
        "github.rest.repos.checkCollaborator\n"
        "getCollaboratorPermissionLevel\n"
    )
    result = parse_script(script)

    assert result["hard_gate"] is True
    assert result["soft_gate"] is True
    assert result["is_sink"] is True


def test_decompose_action_ref_standard_action():
    action_path = "actions/checkout@v2"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "actions/checkout@v2",
        "path": "",
        "ref": "v2",
        "local": False,
        "docker": False,
        "repo": "actions/checkout",
    }
    assert result == expected


def test_decompose_action_ref_local_action():
    action_path = "./local-action"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "./local-action",
        "path": "local-action",
        "ref": "",
        "local": True,
        "docker": False,
        "repo": "test/repo",
    }
    assert result == expected


def test_decompose_action_ref_docker_action():
    action_path = "docker://alpine:3.8"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "docker://alpine:3.8",
        "path": "docker://alpine:3.8",
        "ref": "",
        "local": False,
        "docker": True,
    }
    assert result == expected


def test_decompose_action_ref_standard_action_no_ref():
    action_path = "test/repo"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "test/repo",
        "path": "",
        "ref": "",
        "local": False,
        "docker": False,
        "repo": "test/repo",
    }
    assert result == expected


def test_decompose_action_ref_nested_action_path():
    action_path = "actions/checkout/path/to/action@v2"
    repo_name = "test/repo"
    result = decompose_action_ref(action_path, repo_name)
    expected = {
        "key": "actions/checkout/path/to/action@v2",
        "path": "path/to/action",
        "ref": "v2",
        "local": False,
        "docker": False,
        "repo": "actions/checkout",
    }
    assert result == expected


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_check_sinks_with_sink_in_script(MockConfigManager):
    MockConfigManager().WORKFLOW_PARSING = {
        "SINKS": ["dangerous_function"],
        "SINKS_START": ["start_dangerous"],
    }
    script = "This script calls dangerous_function"
    assert check_sinks(script)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_check_sinks_with_sink_start_in_script(MockConfigManager):
    MockConfigManager().WORKFLOW_PARSING = {
        "SINKS": ["dangerous_function"],
        "SINKS_START": ["start_dangerous"],
    }
    script = "start_dangerous_function()"
    assert check_sinks(script)


@patch("gatox.workflow_parser.utility.ConfigurationManager")
def test_check_sinks_without_sink_in_script(MockConfigManager):
    MockConfigManager().WORKFLOW_PARSING = {
        "SINKS": ["dangerous_function"],
        "SINKS_START": ["start_dangerous"],
    }
    script = "This script is safe"
    assert not check_sinks(script)


def test_parse_github_path_with_ref():
    path = "owner/repo/path/to/file@branch"
    expected_result = ("owner/repo", "path/to/file", "branch")
    assert parse_github_path(path) == expected_result


def test_parse_github_path_without_ref():
    path = "owner/repo/path/to/file"
    expected_result = ("owner/repo", "path/to/file", "main")
    assert parse_github_path(path) == expected_result


def test_parse_github_path_with_only_repo():
    path = "owner/repo"
    expected_result = ("owner/repo", "", "main")
    assert parse_github_path(path) == expected_result


def test_parse_github_path_with_empty_path():
    path = ""
    expected_result = ("", "", "main")
    assert parse_github_path(path) == expected_result


def test_check_sus():
    item = "needs.get_ref.outputs.head-ref"

    assert check_sus(item)


def test_check_sus_false():
    item = "needs.get_permission.allowed"

    assert not check_sus(item)


def test_unsafe():
    item = "github.event.pull_request.title"
    assert checkUnsafe(item)


def test_safe():
    item = "github.event.pull_request.url"
    assert not checkUnsafe(item)


def test_process_runner():
    runner = "custom-mac-m1"
    assert process_runner(runner)


def test_rocess_runner_gh_large():
    runner = ["macos-13-xl"]
    assert not process_runner(runner)


def test_rocess_runner_gh_large1():
    runner = ["ubuntu-24.04"]
    assert not process_runner(runner)


def test_process_runner_list():
    runner = ["custom-mac-m1", "x64"]
    assert process_runner(runner)


def test_process_runner_gh():
    runner = "ubuntu-latest"
    assert not process_runner(runner)
