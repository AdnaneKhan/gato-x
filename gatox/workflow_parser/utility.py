import re
import logging

from datetime import datetime, timedelta

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

logger = logging.getLogger(__name__)

pattern = re.compile(
    r"checkout\s+(\$\{\{)?\s*(\S*([a-z$_]+)\S*)\s*(\}\})?", re.IGNORECASE
)

CONTEXT_REGEX = re.compile(r"\${{\s*([^}]+[^\s])\s?\s*}}")
LARGER_RUNNER_REGEX_LIST = re.compile(
    r"(windows|ubuntu)-(24.04|22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb"
)
MATRIX_KEY_EXTRACTION_REGEX = re.compile(r"{{\s*matrix\.([\w-]+)\s*}}")
STATIC_IF = re.compile(r"^(\$\{\{)?[A-Za-z0-9. ]+(\}\})?$")


@staticmethod
def starts_with_any(value: str, prefixes: list[str]) -> bool:
    """Returns True if 'value' starts with any of the provided prefixes."""
    return any(value.startswith(prefix) for prefix in prefixes)


@staticmethod
def process_matrix(job_def, runs_on):
    """Process case where runner is specified via matrix."""
    try:
        matrix_match = MATRIX_KEY_EXTRACTION_REGEX.search(runs_on)

        if matrix_match:
            matrix_key = matrix_match.group(1)
        else:
            return False
        # Check if strategy exists in the yaml file
        if "strategy" in job_def and "matrix" in job_def["strategy"]:
            matrix = job_def["strategy"]["matrix"]
            # Fail open in case we have step output or fromJSON
            if type(matrix) is str:
                return True

            # Use previously acquired key to retrieve list of OSes
            if matrix_key in matrix:
                os_list = matrix[matrix_key]
            elif "include" in matrix:
                inclusions = matrix["include"]
                os_list = []
                for inclusion in inclusions:
                    if matrix_key in inclusion:
                        os_list.append(inclusion[matrix_key])
            else:
                return False

            # We only need ONE to be self hosted, others can be
            # GitHub hosted
            for key in os_list:
                if type(key) is str:
                    if key not in ConfigurationManager().WORKFLOW_PARSING[
                        "GITHUB_HOSTED_LABELS"
                    ] and not LARGER_RUNNER_REGEX_LIST.match(key):
                        return True
                # list of labels
                elif type(key) is list:
                    return True
    except TypeError:
        logger.error("Error processing matrix job")
        logger.debug(job_def)
        return False


@staticmethod
def is_within_last_day(timestamp_str, format="%Y-%m-%dT%H:%M:%SZ"):
    # Convert the timestamp string to a datetime object
    date = datetime.strptime(timestamp_str, format)

    # Get the current date and time
    now = datetime.now()
    # Calculate the date 1 days ago
    one_day_ago = now - timedelta(days=1)

    # Return True if the date is within the last day, False otherwise
    return one_day_ago <= date <= now


@staticmethod
def return_recent(time1, time2, format="%Y-%m-%dT%H:%M:%SZ"):
    """
    Takes two timestamp strings and returns the most recent one.

    Args:
        time1 (str): The first timestamp string.
        time2 (str): The second timestamp string.
        format (str): The format of the timestamp strings. Default is '%Y-%m-%dT%H:%M:%SZ'.

    Returns:
        str: The most recent timestamp string.
    """
    # Convert the timestamp strings to datetime objects
    date1 = datetime.strptime(time1, format)
    date2 = datetime.strptime(time2, format)

    # Return the most recent timestamp string
    return time1 if date1 > date2 else time2


@staticmethod
def process_runner(runs_on):
    """
    Processes the runner for the job.
    """
    if type(runs_on) is list:
        for label in runs_on:
            if label in ConfigurationManager().WORKFLOW_PARSING["GITHUB_HOSTED_LABELS"]:
                break
            if LARGER_RUNNER_REGEX_LIST.match(label):
                break
        else:
            return True
    elif type(runs_on) is str:
        if runs_on in ConfigurationManager().WORKFLOW_PARSING["GITHUB_HOSTED_LABELS"]:
            return False
        if LARGER_RUNNER_REGEX_LIST.match(runs_on):
            return False
        return True

    return False


@staticmethod
def parse_script(contents: str):
    """Processes run steps for additional context"""
    return_dict = {
        "is_checkout": False,
        "metadata": None,
        "is_sink": False,
        "hard_gate": False,
        "soft_gate": False,
    }

    if not contents or not isinstance(contents, str):
        logging.warning("Invalid contents for script parsing:" + str(contents))
        return return_dict

    if "git checkout" in contents or "pr checkout" in contents:
        match = pattern.search(contents)
        if match:
            ref = match.group(2)

            static_vals = ["base", "main", "master"]

            for prefix in ConfigurationManager().WORKFLOW_PARSING["PR_ISH_VALUES"]:
                if prefix in ref.lower() and not any(
                    substring in ref.lower() for substring in static_vals
                ):
                    return_dict["metadata"] = ref
                    return_dict["is_checkout"] = True

    if "isCrossRepository" in contents and "GITHUB_OUTPUT" in contents:
        return_dict["hard_gate"] = True
    if "github.rest.repos.checkCollaborator" in contents:
        return_dict["soft_gate"] = True
    if "github.rest.orgs.getMembershipForUser" in contents:
        return_dict["soft_gate"] = True
    if "rest.repos.listCollaborators" in contents:
        return_dict["soft_gate"] = True
    if "getCollaboratorPermissionLevel" in contents:
        return_dict["soft_gate"] = True
    if "getMembershipForUserInOrg" in contents:
        return_dict["soft_gate"] = True

    if check_sinks(contents):
        return_dict["is_sink"] = True
    return return_dict


@staticmethod
def check_sinks(script):
    """Check if the script contain a sink."""
    sinks = ConfigurationManager().WORKFLOW_PARSING["SINKS"]
    sinks_start = ConfigurationManager().WORKFLOW_PARSING["SINKS_START"]

    for sink in sinks:
        if sink in script:
            return True

    lines = script.splitlines()
    for line in lines:
        for sink in sinks_start:
            if line.strip().startswith(sink):
                return True
    return False


@staticmethod
def check_sus(item):
    """
    Check if the given item starts with any of the predefined potentially problematic prefixes.

    This method is used to identify potentially unsafe or
    suspicious variables in a GitHub Actions workflow.
    It checks if the item starts with any of the prefixes
    defined in PREFIX_VALUES. These prefixes are typically
    used to reference variables in a GitHub Actions workflow,
    and if a user-controlled variable is referenced
    without proper sanitization, it could lead to a script
    injection vulnerability.

    Args:
        item (str): The item to check.

    Returns:
        bool: True if the item starts with any of the suspicious prefixes, False otherwise.
    """

    PREFIX_VALUES = ["needs.", "env.", "steps.", "jobs."]

    item_lower = item.lower()
    for prefix in PREFIX_VALUES:
        if item_lower.startswith(prefix):
            for safe_string in ConfigurationManager().WORKFLOW_PARSING[
                "SAFE_ISH_CONTEXTS"
            ]:
                if item_lower.endswith(safe_string):
                    break
            else:
                return True
    return False


@staticmethod
def check_risky_regexes(item):
    regexes = ConfigurationManager().WORKFLOW_PARSING["RISKY_CONTEXT_REGEXES"]

    for regex in regexes:
        if re.search(regex, item):
            return True


@staticmethod
def check_pr_ref(item):
    """
    Checks if the given item contains any of the predefined pull request
    related values.

    This method is used to identify if a given item (typically a string)
    contains any of the values defined in PR_ISH_VALUES. These values are
    typically used to reference pull request related data in a GitHub Actions workflow.

    Args:
        item (str): The item to check.

    Returns:
        bool: True if the item contains any of the pull request related values, False otherwise.
    """
    for prefix in ConfigurationManager().WORKFLOW_PARSING["PR_ISH_VALUES"]:
        if prefix in item.lower() and "base" not in item.lower():
            return True
    return False


@staticmethod
def filter_tokens(tokens, strict=False):
    """
    This method filters the tokens from the contents of a step
    in a GitHub workflow for potentially unsafe or suspicious context expressions.

    Parameters:
    contents (str): The contents of a step in a GitHub workflow.

    The method uses a regular expression to find all context expressions in the contents.
    A context expression in a GitHub workflow is a string that starts with '${{' and ends with '}}'.
    The expression inside the curly braces is split by '.' into three parts.
    The first part must be a sequence of alphanumeric characters,
    the second part must also be a sequence of alphanumeric characters,
    and the third part can be any sequence of characters.

    The method then checks each found context expression in two ways:
    1. Against a list of known unsafe context expressions.
        If the context expression is found in the list, it is added to `tokens_knownbad`.
    2. Using the `check_sus` method. If `check_sus` returns
        True for a context expression, it is added to `tokens_sus`.

    The method returns a list of tokens that are either known to be unsafe or are considered suspicious.

    Returns:
    list: A list of unsafe or suspicious context expressions found in the contents.
    """
    # First we get known unsafe
    tokens_knownbad = [
        item
        for item in tokens
        if item.lower() in ConfigurationManager().WORKFLOW_PARSING["UNSAFE_CONTEXTS"]
    ]
    # And then we add anything referenced
    if not strict:
        tokens_sus = [item for item in tokens if check_sus(item)]
        tokens_knownbad.extend(tokens_sus)

    return list(set(tokens_knownbad))


@staticmethod
def getToken(contents):
    """Get the context token from the step."""
    match = CONTEXT_REGEX.search(contents)
    if match:
        return match.group(1).replace(" ", "")
    return contents


@staticmethod
def checkUnsafe(variable):
    """Check if the variable is unsafe."""
    return variable in ConfigurationManager().WORKFLOW_PARSING["UNSAFE_CONTEXTS"]


@staticmethod
def prReviewUnsafe(variable):
    """Check if the variable is unsafe."""
    return (
        variable in ConfigurationManager().WORKFLOW_PARSING["PR_REVIEW_UNSAFE_CONTEXTS"]
    )


@staticmethod
def getTokens(contents):
    """Get the context tokens from the step."""
    if contents:
        finds = CONTEXT_REGEX.findall(contents)

        extension = None
        for find in finds:
            if " || " in find:
                extension = find.split(" || ")
                break

        if extension:
            finds.extend(extension)
        return finds
    else:
        return []


@staticmethod
def check_always_true(if_check):
    """Check if the if check is always true because it uses ${{ }} in combination with
    an expression or uses nested expressions.
    """
    # If it starts with an expression but ends without, then it
    # always will resolve to true.
    if if_check.strip().startswith("${{") and not if_check.endswith("}}"):
        return True


@staticmethod
def check_false_if(if_check):
    checks = ConfigurationManager().WORKFLOW_PARSING["SAFE_IF_CHECKS"]

    for check in checks:
        if check in if_check:
            return True


@staticmethod
def validate_if_check(if_check, variables={}):
    """Function used to validate each if check.
    The strategy here is to "fail open". If we cannot
    determine with certainty the check would fail in an injection
    or pwn request scenario then we return True, because we would rather
    not miss a potential vulnerability.
    """
    if not if_check:
        return True

    if check_false_if(if_check):
        return False

    if check_always_true(if_check):
        return True

    try:
        parser = ExpressionParser(if_check)
    except Exception:
        # Fail open
        return True
    ast_root = parser.get_node()

    try:
        evaluator = ExpressionEvaluator(variables)
        result = evaluator.evaluate(ast_root)
    except NotImplementedError:
        return True
    except Exception:
        return True

    return result


@staticmethod
def __is_within_last_day(timestamp_str, format="%Y-%m-%dT%H:%M:%SZ"):
    # Convert the timestamp string to a datetime object
    date = datetime.strptime(timestamp_str, format)

    # Get the current date and time
    now = datetime.now()
    # Calculate the date 1 days ago
    one_day_ago = now - timedelta(days=1)

    # Return True if the date is within the last day, False otherwise
    return one_day_ago <= date <= now


@staticmethod
def decompose_action_ref(action_path: str, repo_name: str):
    """ """
    action_parts = {
        "key": action_path,
        "path": action_path.split("@")[0] if "@" in action_path else action_path,
        "ref": action_path.split("@")[1] if "@" in action_path else "",
        "local": action_path.startswith("./"),
        "docker": False,
    }

    if "docker://" in action_path:
        # Gato-X doesn't support docker actions
        # and we ignore official GitHub actions for analysis.
        action_parts["docker"] = True
        return action_parts

    if not action_parts["local"]:
        path_parts = action_parts["path"].split("/")

        action_parts["repo"] = "/".join(path_parts[0:2])
        if len(path_parts) > 2:
            action_parts["path"] = "/".join(action_parts["path"].split("/")[2:])
        else:
            # Standard action path in base directory
            action_parts["path"] = ""
    else:
        action_parts["path"] = action_parts["path"][2:]
        action_parts["repo"] = repo_name

    return action_parts


@staticmethod
def parse_github_path(path):
    parts = path.split("@")
    ref = parts[1] if len(parts) > 1 else "main"
    repo_path = parts[0].split("/")
    repo_slug = "/".join(repo_path[0:2])
    file_path = "/".join(repo_path[2:]) if len(repo_path) > 1 else ""

    return repo_slug, file_path, ref
