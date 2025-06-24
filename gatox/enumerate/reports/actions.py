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
from gatox.enumerate.results.issue_type import IssueType
from gatox.enumerate.results.analysis_result import AnalysisResult


class ActionsReport(Report):
    """ """

    ENVIRONMENT_TOCTOU = (
        "The workflow contains an"
        " environment protection rule"
        " but the workflow uses a mutable reference to checkout PR code."
        " This could be exploited via a race condition."
        " See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )
    LABEL_TOCTOU = (
        "The workflow contains "
        "label-based gating but the workflow uses a mutable reference "
        "to check out PR code. This could be exploited via a race condition. "
        "See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )
    PERMISSION_TOCTOU = (
        "The workflow contains a permission check, but uses a mutable reference"
        "to check out PR code. This could be exploited via a race condition. "
        "See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )

    PWN_REQUEST = (
        "The workflow runs on a risky trigger "
        "and might check out the PR code, see if it runs it!"
    )
    ACTIONS_INJECTION = (
        "The workflow uses variables by context expression"
        " within run or script steps. If the step is reachable and the variables are "
        "user controlled, then they can be used to inject arbitrary code into the workflow."
    )

    @classmethod
    def report_actions_risk(cls, result):
        """Report Pwn Requests in the repository in a clean, human readable format."""

        cls.print_divider()
        machine_details = result.to_machine()
        cls.print_header(machine_details)

        pogression = cls.__report_path(machine_details["path"], result)

        for entry in pogression:
            Output.generic(entry)

        if (
            result.issue_type() in [IssueType.PWN_REQUEST, IssueType.ARTIFACT_POISONING]
            and "sink" in machine_details
        ):
            Output.generic(f" Sink: {Output.red(machine_details['sink'])}")

        cls.print_divider()

    @classmethod
    def render_report(cls, risk: AnalysisResult):
        """Render report associated with a particular risk."""
        cls.report_actions_risk(risk)

    @classmethod
    def __report_path(self, path, result: AnalysisResult):
        """Report pwn request candidate jobs, their steps, and if-checks."""

        details = []
        for node in path:
            details.append(f"{'-' * 118}")
            details.append(f" → {Output.bright(node['node'])}")
            if "if" in node:
                details.append(f"   ↪ If: {Output.yellow(node['if'])}")
            if "if_eval" in node:
                details.append(f"   ↪ If Check: {Output.yellow(node['if_eval'])}")

            if "checkout_ref" in node and result.issue_type() in [
                IssueType.PWN_REQUEST,
                IssueType.DISPATCH_TOCTOU,
            ]:
                details.append(f"   ↪ Checkout: {Output.yellow(node['checkout_ref'])}")

            if (
                "contexts" in node
                and result.issue_type() == IssueType.ACTIONS_INJECTION
            ):
                details.append(
                    f"   ↪ Context Vars: {Output.yellow(', '.join(node['contexts']))}"
                )

        return details
