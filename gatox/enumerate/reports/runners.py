"""
Copyright 2024, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from gatox.cli.output import Output
from gatox.enumerate.reports.report import Report
from gatox.models.repository import Repository


class RunnersReport(Report):
    """Generate a report on self-hosted runners attached to the repository."""

    @classmethod
    def report_runners(cls, repo: Repository):
        """Reports Self-Hosted Runners attached to the repository."""
        if repo.accessible_runners or repo.runners:
            cls.print_divider()
            cls.print_header_runner(repo, "Self-Hosted Runners")

            if repo.sh_workflow_names:
                Output.generic(
                    f" Potential Runner Workflows: {Output.yellow(', '.join(repo.sh_workflow_names))}"
                )
            repo.accessible_runners.extend(repo.runners)
            for runner in repo.accessible_runners:
                Output.generic(f"{'-' * 118}")
                if runner.non_ephemeral:
                    Output.generic(f" Runner Type: {Output.red('NON-EPHEMERAL')}")
                else:
                    Output.generic(f" Runner Type: {Output.green('EPHEMERAL')}")

                Output.generic(f" Runner Name: {Output.bright(runner.runner_name)}")
                Output.generic(f" Machine Name: {Output.bright(runner.machine_name)}")
                Output.generic(f" Runner Scope: {Output.bright(runner.runner_type)}")
                Output.generic(f" Runner Groups: {Output.bright(runner.runner_group)}")
                Output.generic(f" Labels: {Output.bright(', '.join(runner.labels))}")

            cls.print_divider()
