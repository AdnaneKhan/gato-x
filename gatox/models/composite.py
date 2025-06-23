import logging
from collections import OrderedDict

from ruamel.yaml.parser import ParserError
from ruamel.yaml import YAML

logger = logging.getLogger(__name__)
yaml_loader = YAML()


class Composite:
    """
    A class to parse GitHub Action ymls.
    """

    def __init__(self, action_yml: str):
        """
        Initializes the CompositeParser instance by loading and parsing the provided YAML file.

        Args:
            action_yml (str): The YAML file to parse.
        """
        self.composite = False
        self.parsed_yml = None
        self.invalid = False

        try:
            self.parsed_yml = yaml_loader.load(action_yml)
        except ParserError as e:
            logger.warning(
                f"Received a parser error while parsing action contents: {str(e)}"
            )
            self.invalid = True
        except Exception as parse_error:
            logger.error(
                f"Received an exception while parsing action contents: {str(parse_error)}"
            )
            self.invalid = True

        if not self.parsed_yml or not isinstance(self.parsed_yml, OrderedDict):
            logger.warning(
                f"Received an invalid action contents, expected OrderedDict, got {type(self.parsed_yml)}"
            )
            self.invalid = True
        else:
            self.composite = self._check_composite()

    def _check_composite(self):
        """
        Checks if the parsed YAML file represents a composite GitHub Actions workflow.

        Returns:
            bool: True if the parsed YAML file represents a composite GitHub
            Actions workflow, False otherwise.
        """
        if "runs" in self.parsed_yml and "using" in self.parsed_yml["runs"]:
            return self.parsed_yml["runs"]["using"] == "composite"
