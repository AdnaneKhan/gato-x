import logging
from collections import OrderedDict
from datetime import datetime

from ruamel.yaml.parser import ParserError
from ruamel.yaml.scanner import ScannerError

from gatox.workflow_parser.yaml import parse_yaml

logger = logging.getLogger(__name__)


class Workflow:
    def __init__(
        self,
        repo_name,
        workflow_contents,
        workflow_name,
        default_branch="main",
        date=None,
        non_default=None,
        special_path=None,
    ):
        self.repo_name = repo_name
        self.invalid = False
        self.parsed_yml = None
        self.workflow_name = workflow_name
        self.special_path = special_path
        if non_default:
            self.branch = non_default
        else:
            self.branch = default_branch

        # Only save off if it's a valid parse. RAM matters.
        try:
            if type(workflow_contents) is bytes:
                workflow_contents = workflow_contents.decode("utf-8")

            self.parsed_yml = parse_yaml(workflow_contents)
            self.workflow_contents = workflow_contents
        except (ParserError, ScannerError) as e:
            logger.warning(
                f"Parser error for workflow {repo_name}:{workflow_name}: {str(e)}"
            )
            self.invalid = True
        except Exception as e:
            logger.error(
                f"Exception while parsing workflow contents {repo_name}:{workflow_name}: {str(e)}"
            )
            self.invalid = True

        if (
            "dependabot" in workflow_name
            and "- package-ecosystem:" in workflow_contents
        ):
            self.invalid = True

        if not self.invalid and not isinstance(self.parsed_yml, OrderedDict):
            logger.warning(
                f"Invalid workflow contents for {repo_name}:{workflow_name}, expected OrderedDict, got {type(self.parsed_yml)}"
            )
            self.invalid = True

        self.date = date if date else datetime.now().isoformat()

    def getPath(self):
        return f".github/workflows/{self.workflow_name}"

    def isInvalid(self):
        return self.invalid
