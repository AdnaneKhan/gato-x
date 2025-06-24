# Security Policy for Gato-X

Gato-X is a command-line tool designed for operator-driven analysis of GitHub Actions workflows. While stability and correctness are important, only certain types of issues are considered security vulnerabilities in the context of this project.

## What Constitutes a Security Issue?

A security issue in Gato-X is defined as a bug or design flaw that could result in one of the following:

- **Credential Exfiltration to Unauthorized Domains:**
  - Any bug that causes Gato-X to send user credentials (such as GitHub PATs) to a domain other than `github.com` or the intended GitHub API endpoints.

- **Command Injection:**
  - Any vulnerability that allows an attacker to execute arbitrary shell commands on the user's system by manipulating repository data, workflow YAML files, or any other user-supplied input processed by Gato-X.

- **Attack Misfire or Unauthorized Exfiltration:**
  - Any error in the attack functionality that causes Gato-X to attack a target repository or organization that the user did not explicitly specify.
  - Any bug that causes exfiltrated credentials or sensitive data to be sent to a URL or endpoint not controlled by the user or not intended by the tool's documented behavior.

## What is **Not** a Security Issue?

- Crashes, hangs, or incorrect results (including false positives/negatives) are **not** considered security issues. These are stability or correctness bugs and should be reported publicly as standard GitHub issues.

## Reporting Security Issues

If you discover a security vulnerability as defined above, **please do not create a public GitHub issue**. Instead, report it privately via GitHub's reporting feature or send an email.

- Email: security@adnanthekhan.com

This allows us to triage and address the issue before public disclosure.

For all other bugs (stability, crashes, incorrect results, etc.), please open a standard issue on the GitHub repository.

Thank you for helping keep Gato-X and its users safe!