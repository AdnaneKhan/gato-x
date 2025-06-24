from gatox.util.arg_utils import ReadableFile, StringType
from gatox.cli.output import Output


def configure_parser_attack(parser):
    """Helper method to add arguments to the attack subparser.

    Args:
        parser: The parser to add attack subarguments to.
    """
    parser.add_argument(
        "--target",
        "-t",
        help="Repository to target in attack.",
        metavar="ORG/REPO",
        required=False,
        type=StringType(80),
    )

    parser.add_argument(
        "--author-name",
        "-a",
        help="Name of the author that all git commits will be made under.\n"
        "Defaults to the user associated with the PAT.",
        metavar="AUTHOR",
        type=StringType(256),
    )

    parser.add_argument(
        "--author-email",
        "-e",
        help="Email that all git commits will be made under.\n"
        "Defaults to the e-mail associated with the PAT.",
        metavar="EMAIL",
        type=StringType(256),
    )

    parser.add_argument(
        "--branch",
        "-b",
        metavar="BRANCH",
        help="Target branch for the attack.\n"
        "For a PR attack, this will be the branch on the target repo the PR\n"
        "will be made to. Defaults to 'main'.\n"
        "For a workflow attack, this will be the branch changes will be\n"
        "pushed to. This cannot be a pre-existing branch. Defaults to a random\n"
        "string.",
        type=StringType(244),
    )

    parser.add_argument(
        "--message",
        "-m",
        metavar="COMMIT_MESSAGE",
        help="Commit message to use. This is displayed in the Actions tab for\n"
        "workflow attacks. Defaults to 'Test Commit'",
        default="Test Commit",
        type=StringType(256),
    )

    parser.add_argument(
        "--command",
        "-c",
        help="Command to execute as part of payload. Defaults to 'whoami'",
    )

    parser.add_argument(
        "--workflow",
        "-w",
        help="Attack by pushing a workflow to a feature branch.",
        action="store_true",
    )

    parser.add_argument(
        "--runner-on-runner",
        "-pr",
        help="Attack with Runner-on-Runner via a Fork Pull Request.",
        action="store_true",
    )

    parser.add_argument(
        "--secrets",
        "-sc",
        help="Attack to exfiltrate pipeline secrets.",
        action="store_true",
    )

    parser.add_argument(
        "--source-branch",
        "-sb",
        default="test",
        help="Name of the PR source branch, this will be displayed as\n"
        f"{Output.bright('user:branch_name')} when seen in the action approval\n"
        "page. Defaults to 'test'",
        type=StringType(244),
    )

    parser.add_argument(
        "--pr-title",
        "-pt",
        default="Test",
        help="Name of the PR that will be created. This will be displayed in\n"
        "the Actions tab and in the closed pull requests list once the\n"
        "tool quickly closes the PR. Defaults to 'Test'",
        metavar="NAME",
    )

    parser.add_argument(
        "--name",
        "-n",
        help="Name of the workflow. This will be shown in the actions tab.\n"
        "Defaults to 'test'",
        type=StringType(64),
    )

    parser.add_argument(
        "--file-name",
        "-fn",
        default="test",
        help=f"Name of yaml file {Output.bright('without extension')} that will be\n"
        "written as part of either attack type. Defaults to 'test'",
        type=StringType(64),
    )

    parser.add_argument(
        "--custom-file",
        "-f",
        help="Path to a yaml workflow that will be uploaded instead of a\n"
        "single shell command. A custom shell command or workflow name\n"
        "cannot be used with this option, as it is specified in the\n"
        "file. Only works for push.",
        metavar="PATH/TO/FILE.YML",
        type=ReadableFile(),
    )

    parser.add_argument(
        "--delete-run",
        "-d",
        help="Delete the resulting workflow run. Requires write permission the target repository.",
        action="store_true",
    )

    parser.add_argument(
        "--timeout",
        "-to",
        metavar="SECONDS",
        help="Timeout, in seconds, to wait for the Workflow to queue and\n"
        "execute. For fork PR attacks, this is the time, in seconds, to wait "
        "for the fork repository to be created. Defaults to '30'",
        default="30",
        type=int,
    )

    parser.add_argument(
        "--c2-repo",
        metavar="C2_REPO",
        help="Name of an existing Gato-X C2 repository in Owner/Repo format.",
        type=StringType(
            140,
            regex=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,39}/[a-zA-Z0-9][a-zA-Z0-9_.-]{1,100}$",
        ),
    )

    parser.add_argument(
        "--interact",
        action="store_true",
        help="Connect to a C2 repository and interact with connected runners.",
        default=False,
    )

    parser.add_argument(
        "--labels",
        metavar="LABELS",
        help="List of labelsp to request for self-hosted runner attacks. Defaults to `self-hosted`.",
        nargs="+",
        default=["self-hosted"],
    )

    parser.add_argument(
        "--target-os",
        metavar="TARGET_OS",
        help="Operating system for Runner-on-Runner attack. Options: windows, linux, osx.",
        choices=["win", "linux", "osx"],
    )

    parser.add_argument(
        "--target-arch",
        metavar="TARGET_ARCH",
        help="Architecture for Runner-on-Runner attack. Options: arm, arm64, x64. Windows and OSX only support arm64 and x64.",
        choices=["arm", "arm64", "x64"],
    )

    parser.add_argument(
        "--keep-alive",
        help="Keep the workflow running after deploying a RoR, this is for exploiting ephemeral self-hosted runners.",
        default=False,
        action="store_true",
    )

    parser.add_argument(
        "--payload-only",
        help="Generate payloads with the specified C2 repository or creates a new one. Used for manually deploying runner on runner.",
        default=False,
        action="store_true",
    )
