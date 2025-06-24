# Gato-X Documentation

Welcome to the Gato-X documentation! This site contains comprehensive information about Gato-X, the GitHub Attack TOolkit - Extreme Edition.

## What is Gato-X?

Gato-X is an offensive security tool designed to identify exploitable GitHub Actions misconfigurations or privilege escalation paths. It focuses on several key areas:

* Self-Hosted Runner enumeration using static analysis of workflow files and analysis of workflow run logs
* Pwn Request and Actions Injection enumeration using static analysis
* Post-compromise secrets enumeration and exfiltration
* Public repository self-hosted runner attacks using Runner-on-Runner (RoR) technique
* Private repository self-hosted runner attacks using RoR technique

The target audience for Gato-X is Red Teamers, Bug Bounty Hunters, and Security Engineers looking to identify misconfigurations.

## Key Features

- **Fast Scanning**: Scan 35-40 thousand repositories in 1-2 hours using a single GitHub PAT
- **Cross-Repository Analysis**: Analyze workflows and reusable actions across repositories
- **Self-Hosted Runner Attacks**: Automate the "Runner-on-Runner" (RoR) technique
- **Post-Compromise Enumeration**: Validate PATs and identify accessible resources

## Documentation Structure

For installation instructions, see the [Installation Guide](user-guide/installation.md).
For command usage, see the [Command Reference](user-guide/command-reference/index.md).
For use cases, see the [Use Cases](user-guide/use-cases/index.md).
For advanced topics, see the [Advanced Topics](user-guide/advanced/index.md).
For contribution guidelines, see the [Contribution Guide](contribution-guide/contributions.md).

## What Gato-X is NOT

Gato-X is _NOT_ a holistic tool to evaluate the GitHub Actions security posture of a repository. Gato-X does not check for best practices like GitHub Actions version pinning, branch protection, secure defaults, and other controls that are important but not directly exploitable. 

Gato-X's enumeration features focus on identifying _exploitable_ issues in a GitHub repository. Exploitable issues mean an issue that can be exploited without any interaction from the maintainer (such as a Pwn Request), or an issue that can be exploited with mild social engineering (such as a GitHub Actions Time-of-Check-Time-of-Use issue).

For general posture evaluation, there are better tools for the job like [OpenSSF ScoreCard](https://github.com/ossf/scorecard).

## Legal and Ethical Considerations

Gato-X is a powerful tool designed for ethical security research purposes only. The `search` and `enumerate` modes are safe to run on public repositories, but attack features should only be used with proper authorization. Always follow responsible disclosure practices when finding vulnerabilities.
