import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


def sed_check():
    """Checks whether `sed` is on the path or not.

    Returns:
        string: Path to `sed`, `None` otherwise.
    """
    retv = shutil.which("sed")

    logger.debug(f"The return value from calling 'sed' was {retv}")
    return retv


def path_check():
    """Checks whether `git` is on the path or not.

    Returns:
        string: Path to `git`, `None` otherwise.
    """
    retv = shutil.which("git")

    logger.debug(f"The return value from calling 'git' was {retv}")
    return retv


def version_check():
    """Calls the git command and returns the version, False otherwise.

    Returns:
        string: Version of git installed on the system and present on PATH.
    """
    result = subprocess.run(["git", "--version"], capture_output=True, text=True)

    if result.returncode != 0:
        logger.error("Call to `git` returned a non-zero return code!")
        return False

    output = result.stdout
    parts = output.strip().split(" ")

    if len(parts) < 3:
        logger.error("Call to `git -v` did not return with expected format!")
        logger.debug(f"The actual output was: {output}!")
        return False

    return parts[2]
