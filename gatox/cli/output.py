import json
import textwrap
import re

from gatox.cli.colors import (
    RED_DASH,
    GREEN_PLUS,
    GREEN_EXCLAIM,
    RED_EXCLAIM,
    BRIGHT_DASH,
    YELLOW_EXCLAIM,
    YELLOW_DASH,
)

from colorama import Style, Fore


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


SPLASH = """

 .d8888b.         d8888 88888888888  .d88888b.         Y88b   d88P 
d88P  Y88b       d88888     888     d88P" "Y88b         Y88b d88P  
888    888      d88P888     888     888     888          Y88o88P   
888            d88P 888     888     888     888           Y888P    
888  88888    d88P  888     888     888     888           d888b    
888    888   d88P   888     888     888     888 888888   d88888b   
Y88b  d88P  d8888888888     888     Y88b. .d88P         d88P Y88b  
 "Y8888P88 d88P     888     888      "Y88888P"         d88P   Y88b 
                                                                   
    By @adnanthekhan - github.com/AdnaneKhan/gato-x                                            
                                                                
"""


class Output(metaclass=Singleton):
    def __init__(self, color: bool = True, suppress: bool = False):
        self.color = color
        self.suppress = suppress

        self.red_dash = RED_DASH if color else "[-]"
        self.red_explain = RED_EXCLAIM if color else "[!]"
        self.green_plus = GREEN_PLUS if color else "[+]"
        self.green_exclaim = GREEN_EXCLAIM if color else "[!]"
        self.bright_dash = BRIGHT_DASH if color else "-"
        self.yellow_exclaim = YELLOW_EXCLAIM if color else "[!]"
        self.yellow_dash = YELLOW_DASH if color else "[-]"

    @classmethod
    def write_json(cls, execution_wrapper, output_json):
        """Writes JSON to path specified earlier.

        Args:
            execution_wrapper (Execution): Wrapper object for Gato
            enumeration run.
            output_json (str): Path to Json file
        Returns:
            True if successful, false otherwise.
        """
        if Output().suppress:
            return True
        if execution_wrapper.user_details:
            with open(output_json, "w") as json_out:
                json_out.write(json.dumps(execution_wrapper.toJSON(), indent=4))
            return True

    @classmethod
    def error(cls, message: str):
        """Prints error text.

        Args:
            message (str): Message to format.
        """
        if Output().suppress:
            return
        print(f"{Output().red_dash} {message}")

    @classmethod
    def info(cls, message: str, end="\n", flush=False):
        """Prints info text, this adds a green [+] to the message.

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"{Output().green_plus} {message}", end=end, flush=flush)

    @classmethod
    def tabbed(cls, message: str):
        """Prints a tabbed message with a bright '-'

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"    {Output().bright_dash} {message}")

    @classmethod
    def header(cls, message: str):
        """Prints a message surrounded by '---'

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"{cls.bright('---')} {message} {cls.bright('---')}")

    @classmethod
    def result(cls, message: str):
        """Prints a result, this is something good that the tool found.

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"{Output().green_plus} {message}")

    @classmethod
    def generic(cls, message: str):
        """Generic output to print block wrapped text."""

        if Output().suppress:
            return

        def get_length_without_color_codes(text):
            # Use regular expressions to remove ANSI color codes
            ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
            text_without_color = ansi_escape.sub("", text)

            # Calculate the length of the string without color codes
            length_without_color = len(text_without_color)

            return length_without_color

        lines = textwrap.wrap(message, width=118)
        for line in lines:
            padding = 118 - get_length_without_color_codes(line)

            if line[0] not in [" ", "-", "=", "-", "~"]:
                print(f"| {line}{' ' * (padding - 1)}|")
            else:
                print(f"|{line}{' ' * padding}|")

    @classmethod
    def owned(cls, message: str):
        """Prints a result, this is means that the tool has found a likely
        vector to own something.

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"{Output().green_exclaim} {message}")

    @classmethod
    def inform(cls, message: str):
        """Used to inform a user.

        Args:
            message (str): The message to print.
        """
        if Output().suppress:
            return
        print(f"{Output().yellow_dash} {message}")

    @classmethod
    def warn(cls, message: str):
        """Used to let the user know something that they should not, but
        unlikely to lead to an exploit.
        """
        if Output().suppress:
            return
        print(f"{Output().yellow_exclaim} {message}")

    @classmethod
    def bright(cls, toformat: str):
        """Highlights the text and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str): Highlighted text.
        """
        if Output().suppress:
            return toformat
        if cls not in cls._instances or Output().color:
            return f"{Style.BRIGHT}{toformat}{Style.RESET_ALL}"
        else:
            return toformat

    @classmethod
    def yellow(cls, toformat: str):
        """Makes the text yellow and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if Output().suppress:
            return toformat
        if cls not in cls._instances or Output().color:
            return f"{Fore.YELLOW}{toformat}{Style.RESET_ALL}"
        else:
            return toformat

    @classmethod
    def blue(cls, toformat: str):
        """Makes the text blue and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if Output().suppress:
            return toformat
        if cls not in cls._instances or Output().color:
            return f"{Fore.CYAN}{toformat}{Style.RESET_ALL}"
        else:
            return toformat

    @classmethod
    def green(cls, toformat: str):
        """Makes the text green and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if Output().suppress:
            return toformat
        if cls not in cls._instances or Output().color:
            return f"{Fore.GREEN}{toformat}{Style.RESET_ALL}"
        else:
            return toformat

    @classmethod
    def red(cls, toformat: str):
        """Makes the text red and returns it.

        Args:
            toformat (str): Message to format.

        Returns:
            (str)): Formatted message.
        """
        if Output().suppress:
            return toformat
        if cls not in cls._instances or Output().color:
            return f"{Fore.RED}{toformat}{Style.RESET_ALL}"
        else:
            return toformat
