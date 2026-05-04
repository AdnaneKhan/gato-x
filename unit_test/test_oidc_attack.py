import re
from unittest.mock import patch

from gatox.attack.oidc.oidc_attack import OIDCAttack
from unit_test.api_mock import make_api_mock


def escape_ansi(line):
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


# Minimal valid JWT with claims: {"sub": "repo:owner/repo:ref:refs/heads/main", "iss": "https://token.actions.githubusercontent.com"}
MOCK_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJyZXBvOm93bmVyL3JlcG86cmVmOnJlZnMvaGVhZHMvbWFpbiIsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20ifQ"
    ".signature"
)


def test_create_oidc_exfil_yaml():
    """Test OIDC exfil YAML generation."""
    attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    yaml_str = attacker.create_oidc_exfil_yaml("evilBranch", "sigstore")

    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in yaml_str
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" in yaml_str
    assert "audience=sigstore" in yaml_str
    assert "oidc_token.txt" in yaml_str
    assert "actions/upload-artifact@v4" in yaml_str
    assert "id-token" in yaml_str


def test_create_oidc_exfil_yaml_custom_audience():
    """Test OIDC exfil YAML with a custom audience."""
    yaml_str = OIDCAttack.create_oidc_exfil_yaml("branch", "sts.amazonaws.com")

    assert "audience=sts.amazonaws.com" in yaml_str
    assert "matrix" not in yaml_str


def test_create_oidc_exfil_yaml_environments():
    """Test OIDC exfil YAML includes a matrix when environments are provided."""
    yaml_str = OIDCAttack.create_oidc_exfil_yaml(
        "branch", "sigstore", ["production", "staging"]
    )

    assert "matrix" in yaml_str
    assert "production" in yaml_str
    assert "staging" in yaml_str
    assert "files-${{ matrix.safe_name }}" in yaml_str
    assert "name: ${{ matrix.environment }}" in yaml_str
    assert "deployment: false" in yaml_str


def test_decode_jwt_claims():
    """Test JWT payload decoding."""
    claims = OIDCAttack._decode_jwt_claims(MOCK_JWT)

    assert claims is not None
    assert claims["sub"] == "repo:owner/repo:ref:refs/heads/main"
    assert claims["iss"] == "https://token.actions.githubusercontent.com"


def test_decode_jwt_claims_invalid():
    """Test JWT decoding returns None for non-JWT input."""
    assert OIDCAttack._decode_jwt_claims("not.a.valid.jwt.at.all") is None
    assert OIDCAttack._decode_jwt_claims("onlytwoparts") is None


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil(mock_api, capsys):
    """Test OIDC exfil full flow."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 0
    mock_api.return_value.action.get_recent_workflow.return_value = 11111111
    mock_api.return_value.action.get_workflow_status.return_value = 1
    mock_api.return_value.action.retrieve_workflow_artifact.return_value = {
        "oidc_token.txt": MOCK_JWT.encode(),
    }

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", None, None, False, "oidc_exfil", "sigstore"
    )

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    assert "OIDC Token Retrieved" in output
    assert MOCK_JWT in output


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_delete_run(mock_api, capsys):
    """Test OIDC exfil with workflow deletion."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 0
    mock_api.return_value.action.get_recent_workflow.return_value = 11111111
    mock_api.return_value.action.get_workflow_status.return_value = 1
    mock_api.return_value.action.retrieve_workflow_artifact.return_value = {
        "oidc_token.txt": MOCK_JWT.encode(),
    }
    mock_api.return_value.action.delete_workflow_run.return_value = True

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", None, None, True, "oidc_exfil", "sigstore"
    )

    mock_api.return_value.action.delete_workflow_run.assert_called_once()


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_baduser(mock_api, capsys):
    """Test OIDC exfil with insufficient token scopes."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo"],
    }

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", None, None, False, "oidc_exfil", "sigstore"
    )

    captured = capsys.readouterr()
    assert "does not have the necessary scopes" in escape_ansi(captured.out)


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_branchexist(mock_api, capsys):
    """Test OIDC exfil where target branch already exists."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 1

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", "exfilbranch", None, False, "oidc_exfil", "sigstore"
    )

    captured = capsys.readouterr()
    assert "Remote branch, exfilbranch, already exists!" in escape_ansi(captured.out)


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_branchfail(mock_api, capsys):
    """Test OIDC exfil where branch check fails."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = -1

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", "exfilbranch", None, False, "oidc_exfil", "sigstore"
    )

    captured = capsys.readouterr()
    assert "Failed to check for remote branch!" in escape_ansi(captured.out)


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_no_artifact(mock_api, capsys):
    """Test OIDC exfil when artifact retrieval fails."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 0
    mock_api.return_value.action.get_recent_workflow.return_value = 11111111
    mock_api.return_value.action.get_workflow_status.return_value = 1
    mock_api.return_value.action.retrieve_workflow_artifact.return_value = {}

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo", None, None, False, "oidc_exfil", "sigstore"
    )

    captured = capsys.readouterr()
    assert "Failed to retrieve OIDC token artifact" in escape_ansi(captured.out)


MOCK_JWT_2 = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJyZXBvOm93bmVyL3JlcG86ZW52aXJvbm1lbnQ6c3RhZ2luZyIsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20ifQ"
    ".signature2"
)


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_environments(mock_api, capsys):
    """Test OIDC exfil with environments de-duplicates identical tokens."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 0
    mock_api.return_value.action.get_recent_workflow.return_value = 11111111
    mock_api.return_value.action.get_workflow_status.return_value = 1

    # production has a unique token; staging has a different token
    mock_api.return_value.action.retrieve_all_workflow_artifacts.return_value = {
        "files-production": {"oidc_token.txt": MOCK_JWT.encode()},
        "files-staging": {"oidc_token.txt": MOCK_JWT_2.encode()},
    }

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo",
        None,
        None,
        False,
        "oidc_exfil",
        "sigstore",
        environments=["production", "staging"],
    )

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    assert MOCK_JWT in output
    assert MOCK_JWT_2 in output
    # Both environments appear in headers
    assert "production" in output
    assert "staging" in output


@patch("gatox.attack.attack.Api", return_value=make_api_mock())
async def test_oidc_exfil_environments_dedup(mock_api, capsys):
    """Test OIDC exfil de-duplicates when two environments return the same token."""
    mock_api.return_value.user.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.commit.get_repo_branch.return_value = 0
    mock_api.return_value.action.get_recent_workflow.return_value = 11111111
    mock_api.return_value.action.get_workflow_status.return_value = 1

    mock_api.return_value.action.retrieve_all_workflow_artifacts.return_value = {
        "files-production": {"oidc_token.txt": MOCK_JWT.encode()},
        "files-staging": {"oidc_token.txt": MOCK_JWT.encode()},
    }

    gh_attacker = OIDCAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.oidc_exfil(
        "targetRepo",
        None,
        None,
        False,
        "oidc_exfil",
        "sigstore",
        environments=["production", "staging"],
    )

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    # Same token — printed only once
    assert output.count(MOCK_JWT) == 1
