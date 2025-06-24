from gatox.attack.cicd_attack import CICDAttack
from gatox.attack.payloads.payloads import Payloads


def test_create_malicious_push_yaml():
    """Test code to create a malicious yaml file"""
    yaml = CICDAttack.create_push_yml("whoami", "testing")

    assert "run: whoami" in yaml


def test_ror_workflow_default():
    workflow = Payloads.create_ror_workflow(
        "foobar",
        "evil",
        "https://example.com",
        runner_labels=["self-hosted", "super-secure"],
    )

    assert "continue-on-error: true" in workflow


def test_ror_workflow_win():
    workflow = Payloads.create_ror_workflow(
        "foobar",
        "evil",
        "https://example.com",
        runner_labels=["self-hosted", "super-secure"],
        target_os="win",
    )

    assert "continue-on-error: true" in workflow
    assert "powershell" in workflow
