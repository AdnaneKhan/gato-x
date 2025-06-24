import argparse
import os
from pathlib import Path
import re
import logging

from colorama import Fore, Style

from gatox.util.arg_utils import read_file_and_validate_lines
from gatox.caching.cache_manager import CacheManager
from gatox.cli.colors import RED_DASH
from gatox.cli.output import Output, SPLASH
from gatox.caching.local_cache_manager import LocalCacheFactory
from gatox.cli.enumeration.config import configure_parser_enumerate
from gatox.cli.search.config import configure_parser_search
from gatox.cli.attack.config import configure_parser_attack
from gatox.cli.app.config import configure_parser_app
from gatox.enumerate.enumerate import Enumerator
from gatox.enumerate.app_enumerate import AppEnumerator
from gatox.attack.attack import Attacker
from gatox.attack.runner.webshell import WebShell
from gatox.attack.secrets.secrets_attack import SecretsAttack
from gatox.search.search import Searcher
from gatox.models.execution import Execution


async def cli(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            f"{Fore.YELLOW}This tool requires a GitHub access token to"
            f" function!{Style.RESET_ALL}\n\nThis can be passed via the"
            ' "GH_TOKEN" environment variable, or if it is not set,\nthen the'
            " application will prompt you for one. App enumeration requires a GitHub App ID and PEM file.\n\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    configure_parser_general(parser)

    parser.add_argument(
        "--api-url",
        "-u",
        help=(
            f"{Fore.RED}{Output.bright('[Experimental]')}\n"
            "Github API URL to target. \n"
            "Defaults to 'https://api.github.com'"
        ),
        metavar="https://api.github-url.com/api/v3",
        required=False,
    )

    attack_parser = subparsers.add_parser(
        "attack",
        help="CI/CD Attack Capabilities",
        aliases=["a"],
        formatter_class=argparse.RawTextHelpFormatter,
    )
    attack_parser.set_defaults(func=attack)

    enumerate_parser = subparsers.add_parser(
        "enumerate",
        help="Enumeration Capabilities",
        aliases=["enum", "e"],
        formatter_class=argparse.RawTextHelpFormatter,
    )
    enumerate_parser.set_defaults(func=enumerate)

    search_parser = subparsers.add_parser(
        "search",
        help="Search Capabilities Using GitHub's API",
        aliases=["s"],
        formatter_class=argparse.RawTextHelpFormatter,
    )
    search_parser.set_defaults(func=search)

    app_parser = subparsers.add_parser(
        "app",
        help=f"{Output.red('[Experimental]')} GitHub App Enumeration Capabilities",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    app_parser.set_defaults(func=app)

    configure_parser_attack(attack_parser)
    configure_parser_enumerate(enumerate_parser)
    configure_parser_search(search_parser)
    configure_parser_app(app_parser)

    arguments = parser.parse_args(args)

    Output(color=not arguments.no_color)
    validate_arguments(arguments, parser)
    print(Output.blue(SPLASH))

    await arguments.func(arguments, subparsers)


def save_workflow_ymls(output_directory):
    for repo in CacheManager().get_repos():
        Path(os.path.join(output_directory, f"{repo}")).mkdir(
            parents=True, exist_ok=True
        )
        for workflow in CacheManager().get_workflows(repo):
            with open(
                os.path.join(output_directory, f"{repo}/{workflow.workflow_name}"), "w"
            ) as wf_out:
                wf_out.write(workflow.workflow_contents)


def validate_arguments(args, parser):
    logging.basicConfig(level=args.log_level)

    # App command has different authentication requirements
    if hasattr(args, "app") and args.app is not None:
        # App command uses App ID + PEM file instead of GH_TOKEN
        gh_token = None  # App command doesn't use this
    else:
        # Regular commands need GH_TOKEN
        if "GH_TOKEN" not in os.environ:
            gh_token = input(
                "No 'GH_TOKEN' environment variable set! Please enter a GitHub"
                " PAT.\n"
            )
        else:
            gh_token = os.environ["GH_TOKEN"]

        if "github_pat_" in gh_token:
            parser.error(
                f"{Fore.RED}[!] Fine-grained PATs are currently not supported!"
            )

        if not (
            re.match("gh[po]_[A-Za-z0-9]{36}$", gh_token)
            or re.match("^[a-fA-F0-9]{40}$", gh_token)
        ):
            if re.match("gh[s]_[A-Za-z0-9]{36}$", gh_token):
                if not (args.machine and args.repository):
                    parser.error(
                        f"{Fore.RED}[!]{Style.RESET_ALL} Gato-X does"
                        " not support App tokens without machine flag."
                    )
                else:
                    Output.info(
                        "Allowing the use of a GitHub App token for single repo enumeration."
                    )
            else:
                parser.error(
                    f"{Fore.RED}[!]{Style.RESET_ALL} Provided GitHub PAT is malformed or unsupported!"
                )

    args_dict = vars(args)
    args_dict["gh_token"] = gh_token

    if args.socks_proxy and args.http_proxy:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You cannot use a SOCKS and HTTP"
            " proxy at the same time!"
        )


async def attack(args, parser):
    parser = parser.choices["attack"]

    if not args.target and not (args.interact or args.payload_only):
        parser.error(
            f"{Fore.RED}[!] You must select a target unless you are interacting with an implant or generating payloads!"
        )

    if not (
        args.workflow
        or args.runner_on_runner
        or args.secrets
        or args.interact
        or args.payload_only
    ):
        parser.error(
            f"{Fore.RED}[!] You must select one of the attack modes, "
            "workflow, runner_on_runner, secrets, or interact."
        )

    if args.custom_file and (args.command or args.name):
        parser.error(
            f"{Fore.RED}[!] A shell command or workflow name"
            f" cannot be used with a custom workflow."
        )

    if args.secrets and args.command:
        parser.error(f"{Fore.RED}[!] A command cannot be used with secrets exfil!.")

    if args.runner_on_runner and args.command:
        parser.error(
            f"{Fore.RED}[!] A command cannot be used with runner-on-runner attacks!."
        )

    if not args.custom_file:
        args.command = args.command if args.command else "whoami"
        args.name = args.name if args.name else "test"

    if args.runner_on_runner and not (args.target_os or args.target_arch):
        parser.error(
            f"{Fore.RED}[!] You must specify a target OS and architecture for runner-on-runner attacks!"
        )

    if args.payload_only and not (args.target_os or args.target_arch):
        parser.error(
            f"{Fore.RED}[!] You must specify a target OS, architecture, and C2 Repo for runner-on-runner payload generation!"
        )

    if args.runner_on_runner:
        if (
            args.target_os == "windows" or args.target_os == "osx"
        ) and args.target_arch == "arm":
            parser.error(
                f"{Fore.RED}[!] Windows and OSX do not support arm32 architecture!"
            )

    timeout = int(args.timeout)

    if args.runner_on_runner or args.payload_only or args.interact:
        if not args.branch:
            args.branch = "main"

        gh_attack_runner = WebShell(
            args.gh_token,
            author_email=args.author_email,
            author_name=args.author_name,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            timeout=timeout,
            github_url=args.api_url,
        )

        if args.payload_only:
            await gh_attack_runner.payload_only(
                args.target_os,
                args.target_arch,
                args.labels,
                c2_repo=args.c2_repo,
                keep_alive=args.keep_alive,
            )
        elif args.runner_on_runner:
            await gh_attack_runner.runner_on_runner(
                args.target,
                args.branch,
                args.pr_title,
                args.source_branch,
                args.message,
                args.target_os,
                args.target_arch,
                args.labels,
                keep_alive=args.keep_alive,
                yaml_name=args.file_name,
                run_name=args.name,
                workflow_name=args.name,
                c2_repo=args.c2_repo,
            )
        elif args.interact:
            if args.c2_repo:
                await gh_attack_runner.interact_webshell(args.c2_repo)
            else:
                parser.error(
                    f"{Fore.RED}[!] You must specify a C2 repo to interact with!"
                )

    elif args.workflow:
        gh_attack_runner = Attacker(
            args.gh_token,
            author_email=args.author_email,
            author_name=args.author_name,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            timeout=timeout,
            github_url=args.api_url,
        )
        await gh_attack_runner.push_workflow_attack(
            args.target,
            args.command,
            args.custom_file,
            args.branch,
            args.message,
            args.delete_run,
            args.file_name,
        )
    elif args.secrets:
        gh_attack_runner = SecretsAttack(
            args.gh_token,
            author_email=args.author_email,
            author_name=args.author_name,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            timeout=timeout,
            github_url=args.api_url,
        )

        await gh_attack_runner.secrets_dump(
            args.target, args.branch, args.message, args.delete_run, args.file_name
        )


async def enumerate(args, parser):
    parser = parser.choices["enumerate"]

    if not (
        args.target
        or args.self_enumeration
        or args.repository
        or args.repositories
        or args.validate
        or args.commit
    ):
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} No enumeration type was specified!"
        )

    # Count enumeration types, treating commit as a modifier for repository
    enumeration_count = sum(
        bool(x)
        for x in [
            args.target,
            args.self_enumeration,
            args.repository or args.commit,  # repository and commit work together
            args.repositories,
            args.validate,
        ]
    )

    if enumeration_count != 1:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You must only select one enumeration type."
        )

    gh_enumeration_runner = Enumerator(
        args.gh_token,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        skip_log=args.skip_runners,
        github_url=args.api_url,
        ignore_workflow_run=args.ignore_workflow_run,
        deep_dive=args.deep_dive,
    )

    exec_wrapper = Execution()
    orgs = []
    repos = []

    if args.cache_restore_file:
        LocalCacheFactory.load_cache_from_file(args.cache_restore_file)
        Output.info(f"Cache restored from file:{args.cache_restore_file}")

    if args.validate:
        orgs = await gh_enumeration_runner.validate_only()
    elif args.self_enumeration:
        orgs, repos = await gh_enumeration_runner.self_enumeration()
    elif args.target:
        # First, determine if the target is an organization or a repository.
        if await gh_enumeration_runner.api.get_user_type(args.target) == "Organization":
            orgs = [await gh_enumeration_runner.enumerate_organization(args.target)]
        else:
            # Otherwise, simply enumerate all repositories belonging to the user.
            repos = await gh_enumeration_runner.enumerate_user(args.target)
    elif args.repositories:
        try:
            repo_list = read_file_and_validate_lines(
                args.repositories, r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"
            )
            repos = await gh_enumeration_runner.enumerate_repos(repo_list)
        except argparse.ArgumentError as e:
            parser.error(
                f"{RED_DASH} The file contained an invalid repository name!"
                f"{Output.bright(e)}"
            )
    elif args.commit:
        if not args.repository:
            parser.error("--commit requires --repository to be specified")
        repo_obj = await gh_enumeration_runner.enumerate_commit(
            args.repository, args.commit
        )
        repos = [repo_obj] if repo_obj else []
    elif args.repository:
        repos = await gh_enumeration_runner.enumerate_repos([args.repository])

    if args.output_yaml:
        save_workflow_ymls(args.output_yaml)

    exec_wrapper.set_user_details(gh_enumeration_runner.user_perms)
    exec_wrapper.add_organizations(orgs)
    exec_wrapper.add_repositories(repos)

    try:
        if args.output_json:
            Output.write_json(exec_wrapper, args.output_json)
    except Exception:
        Output.error(
            "Encountered an error writing the output JSON, this is likely a Gato-X bug."
        )

    if args.cache_save_file:
        LocalCacheFactory.dump_cache(args.cache_save_file)
        Output.info(f"Cache saved to file:{args.cache_save_file}")


async def search(args, parser):
    parser = parser.choices["search"]

    gh_search_runner = Searcher(
        args.gh_token,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        github_url=args.api_url,
    )
    if args.sourcegraph:
        if args.query and args.target:
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You cannot select an organization "
                "with a custom query!"
            )

        results = await gh_search_runner.use_sourcegraph_api(
            organization=args.target, query=args.query
        )
    else:
        if not (args.query or args.target):
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You must select an organization "
                "or pass a custom query!."
            )
        if args.query:
            results = await gh_search_runner.use_search_api(
                organization=args.target, query=args.query
            )
        else:
            results = await gh_search_runner.use_search_api(organization=args.target)

    if results:
        gh_search_runner.present_results(results, args.output_text)


async def app(args, parser):
    """Handler for the app command."""
    parser = parser.choices["app"]

    # Create the app enumerator
    app_enumerator = AppEnumerator(
        app_id=args.app,
        private_key_path=args.pem,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        skip_log=args.skip_runners,
        github_url=args.api_url,
        deep_dive=args.deep_dive,
    )

    exec_wrapper = Execution()

    try:
        await app_enumerator.validate_app()
        if args.installations:
            # List all installations with metadata
            installations = await app_enumerator.list_installations()
            app_enumerator.report_installations(installations)

        elif args.installation:
            # Enumerate specific installation
            installation_repos = await app_enumerator.enumerate_installation(
                args.installation
            )
            if installation_repos:
                Output.result(
                    f"Successfully enumerated installation {args.installation}"
                )
                exec_wrapper.add_repositories(installation_repos)
            else:
                Output.error(f"Failed to enumerate installation {args.installation}")
        # Save output if requested
        if args.output_json:
            try:
                Output.write_json(exec_wrapper, args.output_json)
            except Exception:
                Output.error(
                    "Encountered an error writing the output JSON, this is likely a Gato-X bug."
                )

    except Exception as e:
        Output.error(f"App enumeration failed: {str(e)}")


def configure_parser_general(parser):
    """Helper method to add arguments to all subarguments.

    Args:
        parser: The parser to add the arguments to.
    """
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="CRITICAL",
        required=False,
    )

    parser.add_argument(
        "--socks-proxy",
        "-sp",
        help=(
            "SOCKS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format"
        ),
        required=False,
    )

    parser.add_argument(
        "--http-proxy",
        "-p",
        help=(
            "HTTPS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format."
        ),
        required=False,
    )

    parser.add_argument(
        "--no-color", "-nc", help="Removes all color from output.", action="store_true"
    )
