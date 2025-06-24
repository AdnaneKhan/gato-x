# Gato-X MCP Server

Gato-X provides an MCP (Model Context Protocol) server for advanced integration with tools and agents that support the MCP standard, such as GitHub Copilot Workspace, Claude Desktop, Q CLI, and other AI-driven security automation platforms.

## What is the MCP Server?

The Gato-X MCP server exposes Gato-X's powerful GitHub Actions enumeration capabilities as a set of programmatic tools via the MCP protocol. This allows you to:

- Enumerate organizations, repositories, and tokens
- Validate GitHub PATs
- Integrate Gato-X with other security automation workflows

## Installation

To use the MCP server, you must install Gato-X with the optional `mcp` dependencies:

```bash
pip install "gato-x[mcp]"
```

This will install Gato-X and the required `fastmcp` package for MCP protocol support.

## Running the MCP Server

You can start the MCP server using the following command:

```bash
gato-x-mcp
```

## Adding Gato-X MCP Server to Your MCP Configuration

To use the Gato-X MCP server with an MCP-compatible agent (such as Copilot Workspace), add an entry to your `mcp.json` (or VS Code `settings.json`) like this:

```json
{
  "servers": {
    "gato-x-mcpserver": {
      "type": "stdio",
      "command": "/path/to/python",
      "args": ["-m", "gatox.mcp.mcp_server"],
      "env": {
        "GH_TOKEN": "<your_github_pat>"
      }
    }
  }
}
```

- Replace `/path/to/python` with the path to your Python interpreter (e.g., from your virtual environment).
- Set the `GH_TOKEN` environment variable to your GitHub Personal Access Token (PAT) with the required scopes.

**Tip:** For better security, set `GH_TOKEN` as an environment variable in your shell instead of hardcoding it in the config file.

## Supported MCP Tools

Once running, the Gato-X MCP server exposes tools such as:
- `enumerate_organization`
- `enumerate_repository`
- `enumerate_repositories`
- `validate_pat`
- `self_enumeration`

These tools can be called programmatically or via compatible agent UIs.

## Troubleshooting

- Ensure you have installed the `mcp` extra: `pip install "gato-x[mcp]"`
- Make sure your `GH_TOKEN` is valid and has the necessary scopes for your use case.
- If you encounter issues, check the logs/output of the MCP server for error messages.

For more details, see the [Gato-X repository](https://github.com/AdnaneKhan/gato-x) or the main documentation.
