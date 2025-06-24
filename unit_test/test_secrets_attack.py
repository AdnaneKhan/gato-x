import re

from unittest.mock import patch
from unittest.mock import MagicMock, AsyncMock
from gatox.github.api import Api

from gatox.attack.secrets.secrets_attack import SecretsAttack


# From https://stackoverflow.com/questions/14693701/
# how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
def escape_ansi(line):
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


def test_create_secret_exil_yaml():
    """Test code to create a yaml to exfil repository secrets."""
    attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    # Just use the util method to get our key.
    priv, pub = SecretsAttack._SecretsAttack__create_private_key()

    yaml = attacker.create_exfil_yaml(pub, "evilBranch")

    assert "${{ toJSON(secrets)}}" in yaml
    assert "actions/upload-artifact@v4" in yaml


@patch(
    "gatox.attack.secrets.secrets_attack.SecretsAttack._SecretsAttack__decrypt_secrets"
)
@patch(
    "gatox.attack.secrets.secrets_attack.SecretsAttack._SecretsAttack__create_private_key"
)
@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_secrets_dump(mock_api, mock_privkey, mock_dec, capsys):
    """Test secrets dump functionality."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }
    mock_api.return_value.get_secrets.return_value = [{"name": "TEST_SECRET"}]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = 0
    pub_mock = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuA+sy+VjSRn+2irScEhy
UmS2fwJvBszSTjmS1RS1pDguC2gL0DxasqPdw3vHAzeIArvxg1+IJTthvJX3Ji+7
8YoI2gd7J7eKCD2NbdONrBNKqvj8CJUA4nY4BEbpP3zkThRb0fWyVJktCy+bgmS5
Lo7M/sS7urnh55onw9RwL9ETdWj7W2LdgfgF85DVervaJxrSTMdXVJWAzUiIwWTK
fNBiJ0n3Be1NTc6Q4U8ElI2yKp/Dgl7RfLp/FVAgPh6ARzelaCMqJRLW7Wojh5ik
1pKoJiWqLKUwjLX1IU5Xtnf5PDMSMXv0ytFAop0KCV3sJDZeo40bMmO3tijp0+2x
W0vTeApmhYliYKpeqDWi3tm6Je/aYmZQwVlLHmv/U0UyXk7MYI2g5K8MhlGZcIed
spS/Bmt9h87EyaA+dGbqUssk3PAPhDcT9qJ9bOtuCl/MwEF3G4rE0lvJdk82MP17
SymVapDpPHqlCOXpRJlZ3izm1eT4VzS9IAje/1qZdbGS0XsRbYswAhyaV6uyj3rk
9mDboT7sVz+qzpmeNzD8BoQw3N1fUEwnagag4Z5DCrHwvPK9qr+1kNzYbMf5np88
eLxB/rMtfZCjliw1O0DzkkAvH+HnCgufX594EJsr0LLYF6JasVtWM79EGqJaI5mF
w1M8xrm+PUM5qaWCANScuX8CAwEAAQ==
-----END PUBLIC KEY-----
    """

    mock_api.return_value.retrieve_workflow_artifact.return_value = {
        "lookup.txt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "output_updated.json": "A" * 100,
    }
    mock_api.return_value.get_recent_workflow.return_value = 11111111
    mock_api.return_value.get_workflow_status.return_value = 1
    mock_priv = MagicMock()
    mock_priv.decrypt.return_value = "TestSymKey"
    mock_privkey.return_value = (mock_priv, pub_mock)
    mock_dec.return_value = b'{"TEST_SECRET":"TEST_VALUE"}'

    gh_attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.secrets_dump("targetRepo", None, None, True, "exfil")

    captured = capsys.readouterr()

    print_output = captured.out

    assert "Decrypted and Decoded Secrets:" in escape_ansi(print_output)


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_secrets_dump_baduser(mock_api, capsys):
    """Test secrets dump functionality with bad permissions."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo"],
    }

    gh_attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.secrets_dump("targetRepo", None, None, True, "exfil")

    captured = capsys.readouterr()

    print_output = captured.out

    assert "The user does not have the necessary scopes to conduct this" in escape_ansi(
        print_output
    )


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_secrets_dump_nosecret(mock_api, capsys):
    """Test secrets dump where repo has no secrets."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.get_secrets.return_value = []
    mock_api.return_value.get_repo_org_secrets.return_value = []

    gh_attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.secrets_dump("targetRepo", None, None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "The repository does not have any accessible secrets" in escape_ansi(
        print_output
    )


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_secrets_dump_branchexist(mock_api, capsys):
    """Test secrets dump where exfil branch already exists."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.get_secrets.return_value = [{"name": "TEST_SECRET"}]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = 1

    gh_attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.secrets_dump("targetRepo", "exfilbranch", None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "Remote branch, exfilbranch, already exists!" in escape_ansi(print_output)


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_secrets_dump_branchfail(mock_api, capsys):
    """Test secrets dump where branch check fails."""

    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.get_secrets.return_value = [{"name": "TEST_SECRET"}]
    mock_api.return_value.get_repo_org_secrets.return_value = []
    mock_api.return_value.get_repo_branch.return_value = -1

    gh_attacker = SecretsAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    await gh_attacker.secrets_dump("targetRepo", "exfilbranch", None, True, "exfil")

    captured = capsys.readouterr()
    print_output = captured.out

    assert "Failed to check for remote branch!" in escape_ansi(print_output)
