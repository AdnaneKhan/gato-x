import yaml
import logging

from gatox.workflow_parser.source_map import build_composite_source_map


logger = logging.getLogger(__name__)


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
        try:
            loader = yaml.CSafeLoader(action_yml.replace("\t", "  "))
            node = loader.get_single_node()
            self.source_map = build_composite_source_map(node)
            self.parsed_yml = loader.construct_document(node)
        except (
            yaml.parser.ParserError,
            yaml.scanner.ScannerError,
            yaml.constructor.ConstructorError,
        ):
            self.invalid = True
        except ValueError:
            self.invalid = True
        except Exception as parse_error:
            logging.error(
                f"Received an exception while parsing action contents: {str(parse_error)}"
            )
            self.invalid = True

        if not self.parsed_yml or type(self.parsed_yml) is not dict:
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
