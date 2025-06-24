import argparse
import os
import re


class StringType(object):
    def __init__(self, length_cap, regex=None):
        self.length_cap = length_cap
        self.regex = regex

    def __call__(self, string):
        """Validate the length and regex against the string, and then
        return the value if it is valid.

        Args:
            string (str): String argument to validate.

        Raises:
            ArgumentTypeError: Error if the argument exceeds the maximum length
            or does not match the configured regular expression.
        """
        if self.length_cap and len(string) > self.length_cap:
            raise argparse.ArgumentTypeError(
                f"The maximum length is {self.length_cap} characters!"
            )

        if self.regex and not re.match(self.regex, string):
            raise argparse.ArgumentTypeError("The argument is not in the valid format!")

        return string


class WriteableDir(object):
    def __call__(self, dirpath: str):
        """Checks if the path is of a directory that exists and can be
        written to.

        Args:
            dirpath (str): Path to a directory to check.

        Raises:
            argparse.ArgumentTypeError: _description_
            argparse.ArgumentTypeError: _description_

        Returns:
            str: Same path after validation.
        """

        if os.path.isdir(dirpath):
            if os.access(dirpath, os.W_OK):
                return dirpath
            raise argparse.ArgumentTypeError(
                f"The directory: {dirpath} is not writeable!"
            )
        else:
            raise argparse.ArgumentTypeError(
                f"The directory: {dirpath} does not exist!"
            )


class WritablePath(object):
    def __call__(self, filepath: str) -> str:
        """
        Checks that filepath is writable if it exists, or can be created if it does not exist.

        Args:
            filepath (str): The path to check.

        Raises:
            argparse.ArgumentTypeError: Raised if we cannot create or write to the file.

        Returns:
            str: The validated path.
        """

        parent_dir = os.path.dirname(filepath) or "."

        if os.path.exists(filepath):
            # Check if we can write to it
            if not os.access(filepath, os.W_OK):
                raise argparse.ArgumentTypeError(
                    f"Cannot write to existing file: {filepath}"
                )
        else:
            # Check if parent directory is writable
            if not os.path.isdir(parent_dir):
                raise argparse.ArgumentTypeError(
                    f"Directory does not exist: {parent_dir}"
                )
            if not os.access(parent_dir, os.W_OK):
                raise argparse.ArgumentTypeError(f"Cannot create file at: {filepath}")

        return filepath


class ReadableFile(object):
    def __call__(self, filepath: str):
        """Argument validation function for file paths.

        Args:
            filepath (str): Path to a file to check if the file exists
            and that it can be read.

        Raises:
            argparse.ArgumentTypeError: Raised if the file cannot be read.
            argparse.ArgumentTypeError: Raised if the file does not exist.

        Returns:
            str: Same path after validation.
        """

        if os.path.exists(filepath):
            if os.access(filepath, os.R_OK):
                return filepath
            raise argparse.ArgumentTypeError(f"The file: {filepath} is not readable!")
        else:
            raise argparse.ArgumentTypeError(f"The file: {filepath} does not exist!")


def is_valid_directory(parser, arg):
    if not os.path.isdir(arg):
        parser.error("The directory {} does not exist!".format(arg))
    else:
        # File exists so return the directory
        return arg


def read_file_and_validate_lines(filepath: str, regex: str):
    """Reads a file and validates that each line matches the regular
    expression.

    Args:
        filepath (str): Path to the file.
        regex (str): Regular expression to use.

    Returns:
        list: List of lines that match the regular expression.
    """

    lines = []
    pat = re.compile(regex)

    with open(filepath, "r") as f_in:
        for line in f_in:
            match = pat.match(line)
            if not match:
                raise argparse.ArgumentError(
                    None,
                    f" The line '{line.strip()}' did not match the regular expression!",
                )
            lines.append(match.group(0))
    return lines
