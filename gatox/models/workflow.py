import logging
from collections import OrderedDict
from datetime import datetime

from ruamel.yaml.parser import ParserError
from ruamel.yaml import YAML

logger = logging.getLogger(__name__)
yaml_loader = YAML()


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

            self.parsed_yml = yaml_loader.load(workflow_contents)
            self.workflow_contents = workflow_contents
        except ParserError as e:
            logger.warning(
                f"Received a parser error while parsing workflow contents: {str(e)}"
            )
            self.invalid = True
        except Exception as parse_error:
            logger.error(
                f"Received an exception while parsing workflow contents: {str(parse_error)}"
            )
            self.invalid = True

        if (
            "dependabot" in workflow_name
            and "- package-ecosystem:" in workflow_contents
        ):
            self.invalid = True

        if not self.parsed_yml or not isinstance(self.parsed_yml, OrderedDict):
            logger.warning(
                f"Received an invalid workflow contents, expected OrderedDict, got {type(self.parsed_yml)}"
            )
            self.invalid = True

        self.date = date if date else datetime.now().isoformat()

    def getPath(self):
        return f".github/workflows/{self.workflow_name}"

    def isInvalid(self):
        return self.invalid
