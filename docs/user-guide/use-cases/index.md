# Overview

This section provides an overview of common use cases for Gato-X.

For installation instructions, see the [Installation Guide](../installation.md).
For command usage, see the [Command Reference](../command-reference/index.md).
For advanced topics, see the [Advanced Topics](../advanced/index.md).

## Available Use Cases

- [Scanning for Vulnerabilities](scanning.md) - How to effectively scan repositories for GitHub Actions vulnerabilities
- [Self-Hosted Runner Takeover](runner-takeover.md) - Techniques for exploiting self-hosted runner vulnerabilities
- [Post-Compromise Enumeration](post-compromise.md) - How to enumerate resources after obtaining a GitHub PAT

## Choosing the Right Approach

The approach you take depends on your specific goals:

1. **Security Research**: Use the search and enumerate commands to identify vulnerabilities in public repositories, then report them responsibly.

2. **Red Team Operations**: Use the full suite of tools to simulate attacks against your organization's GitHub infrastructure.

3. **Security Assessment**: Use Gato-X to assess the security posture of your organization's GitHub Actions workflows.

4. **Bug Bounty Hunting**: Search for vulnerabilities in bug bounty programs that include GitHub Actions in scope.

## Ethical Considerations

Always ensure you have proper authorization before using Gato-X's attack features. The search and enumerate features are safe to use on public repositories, but attack features should only be used with explicit permission.
