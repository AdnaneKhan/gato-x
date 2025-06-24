from gatox.cli.output import Fore, Style, Output
from gatox.util.arg_utils import StringType, ReadableFile, WriteableDir, WritablePath


def configure_parser_enumerate(parser):
    """Helper method to add arguments to the enumeration subparser.

    Args:
        parser: sub parser to add arguments to.
    """

    parser.add_argument(
        "--target",
        "-t",
        help="Target an organization to enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}ORGANIZATION{Style.RESET_ALL}",
        type=StringType(39),
    )

    parser.add_argument(
        "--repository",
        "-r",
        help="Target a single repository in org/repo format to enumerate for\n"
        "self-hosted runners.",
        metavar=f"{Fore.RED}ORG/REPO_NAME{Style.RESET_ALL}",
        type=StringType(79, regex=r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"),
    )

    parser.add_argument(
        "--repositories",
        "-R",
        help="A text file containing repositories in org/repo format to\n"
        "enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}PATH/TO/FILE.txt{Style.RESET_ALL}",
        type=ReadableFile(),
    )

    parser.add_argument(
        "--commit",
        help="Check a specific commit for Actions vulnerabilities. Requires --repository.",
        metavar=f"{Fore.RED}SHA{Style.RESET_ALL}",
        type=StringType(40, regex=r"[A-Fa-f0-9]{40}"),
    )

    parser.add_argument(
        "--self-enumeration",
        "-s",
        help=(
            "Enumerate the configured token's access and all repositories or\n"
            "organizations the user has write access to."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--validate",
        "-v",
        help=("Validate if the token is valid and print organization memberships."),
        action="store_true",
    )

    parser.add_argument(
        "--output-yaml",
        "-o",
        help=(
            "Directory to save gathered workflow yml files to. Will be\n"
            f"created in the following format: {Fore.GREEN}"
            f"org/repo/workflow.yml{Style.RESET_ALL}"
        ),
        metavar="DIR",
        type=WriteableDir(),
    )

    parser.add_argument(
        "--skip-runners",
        "-sr",
        help=(
            f"Do {Output.bright('NOT')} enumerate runners via run-log analysis, this will\n"
            "speed up the enumeration, but will miss self-hosted runners for\n"
            "non-admin users."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--machine",
        help=(
            "Run with a GitHub App token, which will allow running single repository\n"
            " enumeration with server-to-server or user-to-server tokens."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--ignore-workflow-run",
        help=(
            "Ignore the `workflow_run` trigger when enumerating repositories.\n"
            "This is useful if you know the organization requires approval for all\n"
            "fork pull requests."
        ),
        action="store_true",
        default=False,
    )

    parser.add_argument(
        "--output-json",
        "-oJ",
        help=("Save enumeration output to JSON file."),
        metavar="JSON_FILE",
        type=StringType(256),
    )

    parser.add_argument(
        "--deep-dive",
        "-dd",
        help=(
            "Perform deep dive static analysis, which includes analyzing non-default branches for Pwn Request vulnerabilities.\n"
            "Git is required on the PATH for this feature."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--cache-restore-file",
        help=(
            "Path to JSON file containing saved reusable action files. This will reduce the need for frequent API requests."
        ),
        metavar="JSON_FILE",
        type=ReadableFile(),
    )

    parser.add_argument(
        "--cache-save-file",
        help=(
            "Path to JSON file to save cache to after executing. Can be the same as the restore file, in which case it will over-write it."
        ),
        metavar="JSON_FILE",
        type=WritablePath(),
    )
