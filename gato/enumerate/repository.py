import logging
import json
import yaml
import signal

from datetime import datetime, timedelta

from gato.notifications import send_slack_webhook
from gato.cli import Output
from gato.models import Repository, Secret, Runner, Workflow
from gato.github import Api
from gato.workflow_parser import WorkflowParser
from gato.caching import CacheManager


logger = logging.getLogger(__name__)


class RepositoryEnum():
    """Repository specific enumeration functionality.
    """

    def __init__(self, api: Api, skip_log: bool, output_yaml):
        """Initialize enumeration class with instantiated API wrapper and CLI
        parameters.

        Args:
            api (Api): GitHub API wraper object.
        """
        self.api = api
        self.skip_log = skip_log
        self.output_yaml = output_yaml

    def __perform_runlog_enumeration(self, repository: Repository, workflows: list):
        """Enumerate for the presence of a self-hosted runner based on
        downloading historical runlogs.

        Args:
            repository (Repository): Wrapped repository object.
            workflows (list): List of workflows that execute on self-hosted runner.

        Returns:
            bool: True if a self-hosted runner was detected.
        """
        runner_detected = False
        wf_runs = []

        wf_runs = self.api.retrieve_run_logs(
            repository.name, short_circuit=True, workflows=workflows
        )

        if wf_runs:
            for wf_run in wf_runs:
                runner = Runner(
                    wf_run['runner_name'],
                    wf_run['runner_type'],
                    wf_run['token_permissions'],
                    runner_group=wf_run['runner_group'],
                    machine_name=wf_run['machine_name'],
                    labels=wf_run['requested_labels'],
                    non_ephemeral=wf_run['non_ephemeral']
                )

                repository.add_accessible_runner(runner)
            runner_detected = True

        return runner_detected
    
    # def __augment_composite_info(self, repository, comp_actions, comp_action_contents):
    #     """
    #     """
    #     for comp_action in comp_actions:
    #         if comp_action['key'] in comp_action_contents:
    #             contents = comp_action_contents[comp_action['key']]
            
    #             parsed_action = CompositeParser(contents)
    #             if parsed_action.is_composite():
    #                 composite_injection = parsed_action.check_injection()
    #                 if composite_injection:
    #                     Output.result(
    #                         f"The composite action {Output.bright(comp_action['key'])} referenced by {repository.name} runs on a risky trigger "
    #                         f"and uses values by context within run/script steps!"
    #                     )

    #                     #injection_package = {
    #                     #    "composite_action_name": action,
    #                     #    "details": composite_injection
    #                     #}

    #                     #repository.set_injection(injection_package)
    #                     # Output.tabbed(f"Examine the variables and gating: " + json.dumps(composite_injection, indent=4))
    #                     # Output.info(f"You can access the composite action at: "
    #                     #     f"{repository.repo_data['html_url']}/blob/"
    #                     #     f"{repository.repo_data['default_branch']}/"
    #                     #     f"{comp_action['key']}"
                        # )
    def __perform_yml_enumeration(self, repository: Repository):
        """Enumerates the repository using the API to extract yml files. This
        does not generate any git clone audit log events.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            list: List of workflows that execute on sh runner, empty otherwise.
        """
        runner_wfs = []

        if  CacheManager().is_repo_cached(repository.name):
            ymls = CacheManager().get_workflows(repository.name)
        else:
            ymls = self.api.retrieve_workflow_ymls(repository.name)

        for workflow in ymls:
            try:
                parsed_yml = WorkflowParser(workflow.workflow_contents, repository.name, workflow.workflow_name)
                self_hosted_jobs = parsed_yml.self_hosted()

                # composite_actions = parsed_yml.extract_composite_actions()
                # if composite_actions:
                #     comp_action_contents = self.api.retrieve_composite_actions(
                #         repository.name, composite_actions
                #     )
                #     if comp_action_contents:
                #         self.__augment_composite_info(repository, composite_actions, comp_action_contents)

                wf_injection = parsed_yml.check_injection()

                workflow_url = f"{repository.repo_data['html_url']}/blob/{repository.repo_data['default_branch']}/.github/workflows/{parsed_yml.wf_name}"
                pwn_reqs = parsed_yml.check_pwn_request()

                # We aren't interested in pwn request or injection vulns in forks
                # they are likely not viable due to actions being disabled or there
                # is no impact.
                skip_injection = False
                if pwn_reqs or wf_injection:
                    if repository.is_fork():
                        skip_injection = True
            

                if wf_injection and not skip_injection:
                    Output.result(
                        f"The workflow {Output.bright(parsed_yml.wf_name)} runs on a risky trigger "
                        f"and uses values by context within run/script steps!"
                    )

                    injection_package = {
                        "workflow_name": parsed_yml.wf_name,
                        "workflow_url": workflow_url,
                        "details": wf_injection
                    }

                    update_date = self.api.get_file_last_updated(repository.name, f".github/workflows/{parsed_yml.wf_name}")
                    if self.is_within_last_3_days(update_date):
                        send_slack_webhook(injection_package)

                    repository.set_injection(injection_package)

                    Output.tabbed(f"Examine the variables and gating: " + json.dumps(wf_injection, indent=4))
                    Output.info(f"You can access the workflow at: "
                        f"{repository.repo_data['html_url']}/blob/"
                        f"{repository.repo_data['default_branch']}/"
                        f".github/workflows/{parsed_yml.wf_name}"
                    )
                if pwn_reqs and not skip_injection:
                    Output.result(
                        f"The workflow {Output.bright(parsed_yml.wf_name)} runs on a risky trigger "
                        f"and might check out the PR code, see if it runs it!"
                    )
                    Output.info(f'Trigger(s): {pwn_reqs["triggers"]}')
                    for candidate, details in pwn_reqs['candidates'].items():
                        Output.info(f'Job: {candidate}')
                        
                        if details.get('if_check', ''):
                            Output.info(f'Job if check: {details["if_check"]}')
                        for step in details['steps']:
                            Output.tabbed(f'Ref: {step["ref"]}')
                            if 'if_check' in step and step['if_check']:
                               Output.tabbed(f'If check: {step["if_check"]}')
                            
                        
                    pwn_request_package = {
                        "workflow_name": parsed_yml.wf_name,
                        "workflow_url": workflow_url,
                        "details": pwn_reqs
                    }

                    # update_date = self.api.get_file_last_updated(repository.name, f".github/workflows/{parsed_yml.wf_name}")
                    # if self.is_within_last_7_days(update_date):
                    #     send_slack_webhook(pwn_request_package)

                    repository.set_pwn_request(pwn_request_package)

                    Output.info(f"You can access the workflow at: "
                        f"{repository.repo_data['html_url']}/blob/"
                        f"{repository.repo_data['default_branch']}/"
                        f".github/workflows/{parsed_yml.wf_name}"
                    )

                if self_hosted_jobs:
                    runner_wfs.append(workflow.workflow_name)

                    if self.output_yaml:
                        success = parsed_yml.output(self.output_yaml)
                        if not success:
                            logger.warning("Failed to write yml to disk!")

                
            # At this point we only know the extension, so handle and
            # ignore malformed yml files.
            except (yaml.parser.ParserError, yaml.scanner.ScannerError) as parse_error:
                Output.warn(f"Attempted to parse invalid yaml for {workflow.workflow_name}!")
            except Exception as general_error:
                Output.error("Encountered a Gato error (likely a bug) while parsing a workflow:")
                import traceback
                traceback.print_exc()
                print(f"{workflow.workflow_name}: {str(general_error)}")

        return runner_wfs

    def is_within_last_3_days(self, timestamp_str, format='%Y-%m-%dT%H:%M:%SZ'):
        # Convert the timestamp string to a datetime object
        date = datetime.strptime(timestamp_str, format)

        # Get the current date and time
        now = datetime.now()

        # Calculate the date 7 days ago
        seven_days_ago = now - timedelta(days=3)

        # Return True if the date is within the last 7 days, False otherwise
        return seven_days_ago <= date <= now

    def enumerate_repository(self, repository: Repository, large_org_enum=False):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            large_org_enum (bool, optional): Whether to only 
            perform run log enumeration if workflow analysis indicates likely
            use of a self-hosted runner. Defaults to False.
        """
        runner_detected = False

        repository.update_time()

        if not repository.can_pull():
            Output.error("The user cannot pull, skipping.")
            return

        if repository.is_admin():
            runners = self.api.get_repo_runners(repository.name)

            if runners:
                repo_runners = [
                    Runner(
                        runner,
                        machine_name=None,
                        os=runner['os'],
                        status=runner['status'],
                        labels=runner['labels']
                    )
                    for runner in runners
                ]

                repository.set_runners(repo_runners)

        workflows = self.__perform_yml_enumeration(repository)

        if len(workflows) > 0:
            repository.add_self_hosted_workflows(workflows)
            runner_detected = True

        if not self.skip_log:
            # If we are enumerating an organization, only enumerate runlogs if
            # the workflow suggests a sh_runner.
            if large_org_enum and runner_detected:
                self.__perform_runlog_enumeration(repository, workflows)

            # If we are doing internal enum, get the logs, because coverage is
            # more important here and it's ok if it takes time.
            elif not repository.is_public() or not large_org_enum:
                runner_detected = self.__perform_runlog_enumeration(repository, workflows)

        if runner_detected:
            # Only display permissions (beyond having none) if runner is
            # detected.
            repository.sh_runner_access = True

    def enumerate_repository_secrets(
            self, repository: Repository):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if repository.can_push():
            secrets = self.api.get_secrets(repository.name)

            repo_secrets = [
                Secret(secret, repository.name) for secret in secrets
            ]

            repository.set_secrets(repo_secrets)

            org_secrets = self.api.get_repo_org_secrets(repository.name)
            org_secrets = [
                Secret(secret, repository.org_name)
                for secret in org_secrets
            ]

            if org_secrets:
                repository.set_accessible_org_secrets(org_secrets)

    def construct_workflow_cache(self, yml_results):
        """Creates a cache of workflow yml files retrieved from graphQL. Since
        graphql and REST do not have parity, we still need to use rest for most
        enumeration calls. This method saves off all yml files, so during org
        level enumeration if we perform yml enumeration the cached file is used
        instead of making github REST requests. 

        Args:
            yml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """

        cache = CacheManager()
        for result in yml_results:
            # If we get any malformed/missing data just skip it and 
            # Gato will fall back to the contents API for these few cases.
            if not result:
                continue
                
            if 'nameWithOwner' not in result:
                continue

            if 'isArchived' in result and result['isArchived']:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)
            # Empty means no yamls, so just skip.
            if not result['object']:
                continue

            for yml_node in result['object']['entries']:
                yml_name = yml_node['name']
                if yml_name.lower().endswith('yml') or yml_name.lower().endswith('yaml'):
                    contents = yml_node['object']['text']
                    wf_wrapper = Workflow(owner, contents, yml_name)
                    cache.set_workflow(owner, yml_name, wf_wrapper)
            repo_data = {
                'full_name': result['nameWithOwner'],
                'html_url': result['url'],
                'visibility': 'private' if result['isPrivate'] else 'public',
                'default_branch': result['defaultBranchRef']['name'],
                'fork': result['isFork'],
                'permissions': {
                    'pull': result['viewerPermission'] == 'READ' or result['viewerPermission'] == 'TRIAGE' or result['viewerPermission'] == 'WRITE' or result['viewerPermission'] == 'ADMIN',
                    'push': result['viewerPermission'] == 'WRITE' or result['viewerPermission'] == 'ADMIN',
                    'admin': result['viewerPermission'] == 'ADMIN'
                },
                'archived': result['isArchived'],
                'isFork': False
            }

            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)