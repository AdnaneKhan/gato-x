# Overview

Welcome to the Gato-X Command Reference. This section provides detailed usage information for each command.

For installation instructions, see the [Installation Guide](../installation.md).
For use cases, see the [Use Cases](../use-cases/index.md).
For advanced topics, see the [Advanced Topics](../advanced/index.md).

# Command Reference

Gato-X provides three main commands, each with its own set of options:

1. [Search Command](search.md) - Find repositories with potential vulnerabilities
2. [Enumerate Command](enumerate.md) - Analyze repositories for exploitable issues
3. [Attack Command](attack.md) - Execute attacks against vulnerable repositories

## Common Options

These options are available across all commands:

| Option | Description |
|--------|-------------|
| `--log-level` | Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `--socks-proxy`, `-sp` | SOCKS proxy to use for requests in HOST:PORT format |
| `--http-proxy`, `-p` | HTTPS proxy to use for requests in HOST:PORT format |
| `--no-color`, `-nc` | Removes all color from output |
| `--api-url`, `-u` | GitHub API URL to target (defaults to https://api.github.com) |

## Basic Usage

The general syntax for Gato-X commands is:

```bash
gato-x [command] [options]
```

Where `[command]` is one of:
- `search` or `s` - Search for repositories
- `enumerate`, `enum`, or `e` - Enumerate repositories for vulnerabilities
- `attack` or `a` - Execute attacks against vulnerable repositories

## Getting Help

To see the available options for any command, use the `-h` or `--help` flag:

```bash
gato-x --help
gato-x search --help
gato-x enumerate --help
gato-x attack --help
```

For detailed information about each command, refer to the specific command pages linked above.
