# Post-Compromise Enumeration

This guide explains how to use Gato-X for post-compromise enumeration after obtaining a GitHub Personal Access Token (PAT).

> **Note**: This guide is intended for authorized security testing only. Always ensure you have proper permission before using these techniques.

## Overview

If you obtain a GitHub PAT during a security assessment or penetration test, Gato-X can help you:

1. Validate the token and identify its permissions
2. Enumerate accessible repositories and organizations
3. Identify repositories with administrative access
4. Discover accessible secrets
5. Find potential privilege escalation paths

## Validating a Token

To validate a token and see its basic permissions:

```bash
export GH_TOKEN=<the_token>
gato-x e -v
```

This will show:
- Whether the token is valid
- The username associated with the token
- Organization memberships
- Basic permission information

## Self-Enumeration

To perform comprehensive enumeration of all resources accessible with the token:

```bash
gato-x e -s
```

This command:
- Enumerates all repositories the user has access to
- Identifies repositories with administrative access
- Shows accessible secrets (if the user has write access)
- Identifies self-hosted runners the user can access

## Extracting Secrets

If you have write access to a repository, you can extract its secrets:

```bash
gato-x a --secrets --target ORG/REPO
```

This will:
1. Create a new branch in the repository
2. Push a workflow that prints all available secrets
3. Execute the workflow
4. Retrieve the secrets from the workflow logs
5. Delete the workflow run (if requested with `-d`)

## Privilege Escalation

### Finding Vulnerable Workflows

To identify workflows that might allow privilege escalation:

```bash
gato-x e -t TargetOrg
```

Look for:
- Workflows with `pull_request_target` triggers without proper checks
- Workflows that use `GITHUB_TOKEN` with elevated permissions
- Self-hosted runners that you can access

### Exploiting Vulnerable Workflows

If you find a vulnerable workflow, you can exploit it using the appropriate attack command:

```bash
gato-x a --workflow --target ORG/REPO --command "your_command"
```

## Lateral Movement

### Identifying Connected Repositories

Look for:
- Repositories that use reusable workflows from repositories you control
- Repositories that use GitHub Apps you have access to
- Organizations where you have admin access to some repositories but not others

### Accessing Self-Hosted Runners

If you identify accessible self-hosted runners, you can attempt to compromise them:

```bash
gato-x a --runner-on-runner --target ORG/REPO --target-os linux --target-arch x64
```

## Persistence

To maintain access even if the original PAT is revoked:

1. Create new PATs if you have access to the user account
2. Deploy GitHub Apps to repositories you control
3. Add collaborators to repositories you have admin access to
4. Deploy self-hosted runners that you control

## Covering Your Tracks

To minimize detection:

- Use the `--delete-run` option when executing attack workflows
- Remove any branches you created after exploitation
- Be mindful of audit logs that record your actions

## Reporting

When conducting authorized security assessments:

1. Document all findings thoroughly
2. Include evidence of access without including actual secrets
3. Provide clear remediation recommendations
4. Follow the organization's reporting procedures
