# GitHub Fine-Grained Personal Access Tokens

GitHub Fine-Grained Personal Access Tokens (PATs) represent a more secure and granular approach to GitHub API authentication compared to classic PATs. This document covers what fine-grained tokens are, how they work, and how Gato-X leverages them for security enumeration.

## What are Fine-Grained PATs?

Fine-grained PATs were introduced by GitHub to provide more precise permission control over API access. Unlike classic PATs that use broad scopes (like `repo`, `admin:org`), fine-grained tokens allow you to specify exact permissions for specific repositories or organizations.

### Key Differences from Classic PATs

| Feature | Classic PATs | Fine-Grained PATs |
|---------|-------------|-------------------|
| **Scope Granularity** | Broad scopes (e.g., `repo` gives access to all repos) | Specific permissions per repository/organization |
| **Resource Selection** | All accessible resources | Explicitly selected repositories/organizations |
| **Permission Types** | Fixed scope combinations | Granular permission matrix (read/write per resource type) |
| **Token Format** | `ghp_` prefix | `github_pat_` prefix |
| **Expiration** | Optional (can be permanent) | Maximum 1 year, recommended shorter periods |

### Fine-Grained Permission Model

Fine-grained tokens use a permission model based on:

- **Resource Types**: Contents, Issues, Pull Requests, Actions, Secrets, etc.
- **Permission Levels**: None, Read, Write (where applicable)
- **Scope**: Repository-specific or organization-specific

Common fine-grained permissions include:
- `contents:read` / `contents:write` - Repository contents and commits
- `issues:read` / `issues:write` - Issues and issue comments
- `pull_requests:read` / `pull_requests:write` - Pull requests and reviews
- `actions:read` / `actions:write` - GitHub Actions workflows and runs
- `secrets:read` - Repository and organization secrets (read-only)
- `administration:read` - Repository administration settings
- `variables:read` / `variables:write` - Repository and organization variables

One important aspect of fine-grained tokens is that a token with any permissions will always have `metadata` read.

The API endpoint to retrieve repositories for the authenticated user only requires this permission. This allows
Gato-X to build an initial set of repositories for further enumeration. While it will return all public repos, it will also return private repos that the token has access to. This could be because the user configured the token to allow access to all user / org repos OR they expliticly opted that repo in.

## How Gato-X Handles Fine-Grained Tokens

Gato-X automatically detects fine-grained tokens by their `github_pat_` prefix and uses specialized enumeration techniques optimized for the fine-grained permission model.

### Token Detection

```python
if "github_pat" in args.gh_token:
    await enumerate_finegrained(args, parser)
else:
    await enumerate_classic(args, parser)
```

### Fine-Grained Enumeration Process

1. **Token Validation**: Verify the token is valid and get user information
2. **Repository Discovery**: Find accessible repositories (public and private)
3. **Write Access Detection**: Check for write permissions on public repositories via collaborators endpoint
4. **Permission Probing**: Systematically test various endpoints to detect available permissions
5. **Workflow Analysis**: Enumerate accessible repositories for GitHub Actions workflows and secrets

### Permission Probing Strategy

Gato-X uses a multi-stage approach to detect fine-grained permissions.

#### Stage 1: Read Permission Detection
Gato-X probes various GET endpoints to detect read permissions:

```python
private_probe_map = {
    "contents:read": f"/repos/{repo}/commits",
    "issues:read": f"/repos/{repo}/issues", 
    "pull_requests:read": f"/repos/{repo}/pulls",
    "actions:read": f"/repos/{repo}/actions/workflows",
    "secrets:read": f"/repos/{repo}/actions/secrets",
    "administration:read": f"/repos/{repo}/actions/permissions",
    "variables:read": f"/repos/{repo}/actions/variables",
    "deployments:read": f"/repos/{repo}/deployments",
    "webhooks:read": f"/repos/{repo}/hooks"
}
```

#### Stage 2: Write Permission Detection
For each detected read permission, Gato-X attempts to detect corresponding write permissions:

- **Contents Write**: Create a blob via `/repos/{repo}/git/blobs`
- **Issues Write**: Attempt to PATCH an existing issue with no changes
- **Pull Requests Write**: Attempt to PATCH an existing PR with no changes  
- **Actions Write**: Get and re-set OIDC customization settings

Each probe is effectively a no-op. The issues, PR and actions probe do not change anything, and the events do not trigger audit logs events (as of writing).

The contents write probe creates a small dangling blob in the Git database.

#### Public Repository Handling

For public epositories, Gato-X performs directly skips to permission probes for scopes such as issues, pull_request, and actions because most public repo read endpoints always succeed regardless of the token's scopes.


## Security Implications

### From a Defender's Perspective

Fine-grained tokens provide several security benefits:

1. **Principle of Least Privilege**: Tokens can be scoped to exactly the permissions needed
2. **Reduced Blast Radius**: Compromised tokens have limited access scope
3. **Better Auditability**: Clearer permission boundaries make access reviews easier
4. **Forced Expiration**: Maximum 1-year expiration reduces long-term exposure risk

### From an Attacker's Perspective  

Fine-grained tokens present both challenges and opportunities:

**Challenges:**
- More restrictive permissions may limit attack surface
- Shorter expiration times reduce persistence
- Resource-specific access may prevent lateral movement

**Opportunities:**
- Organizations may over-grant permissions during initial setup
- Write permissions to specific repos can still be highly valuable
- Actions and secrets access remains critical for supply chain attacks

## Common Escalation Scenarios

### Scenario 1: Development Token
A developer creates a fine-grained token for their CI/CD pipeline:
- **Permissions**: `contents:write`, `actions:write` on specific repositories
- **Gato-X Detection**: Will identify write access to repository contents and Actions workflows
- **Security Risk**: Potential for code injection by altering scripts on non-default branches and triggering `workflow_dispatch` events.

### Scenario 2: Bot Account Token
An automation bot has read access across multiple repositories:
- **Permissions**: `contents:read`, `issues:read`, `pull_requests:read` on organization repos
- **Gato-X Detection**: Will enumerate all accessible repositories and their contents

## Best Practices for Defense

1. **Regular Token Audits**: Review active fine-grained tokens and their permissions
2. **Minimal Permissions**: Grant only the minimum permissions required
3. **Short Expiration**: Use the shortest practical expiration periods
4. **Repository Scoping**: Limit tokens to specific repositories when possible
5. **Monitoring**: Implement logging and alerting for token usage patterns
6. **Rotation**: Establish regular token rotation procedures

## Understanding Gato-X Output

When Gato-X enumerates a fine-grained token, the output includes:

- **User Information**: Token owner and expiration details
- **Repository Access**: List of accessible repositories (public/private)
- **Detected Permissions**: Specific fine-grained permissions identified
- **Write Access Summary**: Repositories with write+ access
- **Workflow Details**: GitHub Actions workflows and potential attack vectors

**Example output:**

```
[+] Starting fine-grained token enumeration
[+] The authenticated user is: SomeUser
[+] Token expiration: 2025-09-07 15:59:53 -0400
[+] Checking write+ access to public repositories...
    - Write+ access to gatoxtest/repo1
    - Write+ access to gatoxtest/repo2
[+] Token has access to 2 private repo(s).
[+] Probing endpoints to detect scopes...
    -  actions:write ✅
    -  contents:write ✅
    -  issues:read ✅
    -  pull_requests:read ✅
```

## Conclusion

Fine-grained PATs represent a significant improvement in GitHub's security model, but they also require updated approaches for both security testing. Gato-X's specialized fine-grained enumeration capabilities help security teams understand the true scope and risk of these tokens in their environment.

By understanding how fine-grained tokens work and how Gato-X enumerates them, security professionals can better assess their GitHub security posture and implement appropriate controls.