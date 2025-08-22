import asyncio
import sys

from gatox.cli import cli


def entry():
    return asyncio.run(cli.cli(sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(entry())
