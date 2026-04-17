from gatox.util.arg_utils import StringType


def configure_parser_persistence(parser):
    """Helper method to add arguments to the persistence subparser.

    Args:
        parser: The parser to add persistence subarguments to.
    """
    parser.add_argument(
        "--target",
        "-t",
        help="Repository to target for persistence in ORG/REPO format.",
        metavar="ORG/REPO",
        required=True,
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

    # Persistence technique options - these are mutually exclusive
    technique_group = parser.add_mutually_exclusive_group(required=True)

    technique_group.add_argument(
        "--collaborator",
        help="Invite outside collaborators to the repository.\n"
        "Requires admin privileges on the target repository.",
        nargs="+",
        metavar="USERNAME",
    )

    technique_group.add_argument(
        "--deploy-key",
        help="Create a read/write deploy key for the repository.\n"
        "Requires admin privileges on the target repository.",
        action="store_true",
    )

    parser.add_argument(
        "--key-title",
        "-k",
        help="Title for the deploy key. Defaults to 'Gato-X Deploy Key'.",
        metavar="TITLE",
        type=StringType(100),
    )

    parser.add_argument(
        "--key-path",
        "-p",
        help="Path to save the private key file (required for --deploy-key).",
        metavar="PATH",
        type=StringType(256),
    )

    parser.add_argument(
        "--permission",
        help="Permission level for collaborator invitations (pull, triage, push, maintain, admin).\n"
        "Defaults to 'admin'.",
        choices=["pull", "triage", "push", "maintain", "admin"],
        default="admin",
        metavar="LEVEL",
    )
