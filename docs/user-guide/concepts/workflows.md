# Understanding GitHub Actions Workflows

This page provides a comprehensive overview of GitHub Actions workflows in the context of security analysis and vulnerability detection with Gato-X.

## What are GitHub Actions Workflows?

GitHub Actions workflows are automated processes defined in YAML files that run in response to specific events in your repository. They are located in the `.github/workflows/` directory and form the core of GitHub's CI/CD platform.

### Basic Workflow Structure

A typical workflow consists of:

```yaml
name: Example Workflow          # Workflow name
on:                            # Event triggers
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:                          # Collection of jobs
  build:                       # Job ID
    runs-on: ubuntu-latest     # Runner environment
    steps:                     # Sequence of tasks
      - uses: actions/checkout@v4    # Action step
      - name: Run tests              # Script step
        run: npm test
```

## Workflow Components

### Event Triggers (`on`)

Event triggers determine when a workflow runs. Common triggers include:

- **`push`**: Runs when code is pushed to specified branches
- **`pull_request`**: Runs when a pull request is opened, synchronized, or closed
- **`pull_request_target`**: Similar to `pull_request` but runs with base repository permissions ⚠️
- **`issue_comment`**: Runs when comments are added to issues or pull requests ⚠️
- **`workflow_dispatch`**: Allows manual triggering
- **`schedule`**: Runs on a schedule using cron syntax
- **`workflow_run`**: Triggered by the completion of another workflow

### Jobs

Jobs are collections of steps that run on the same runner. Key properties:

- **`runs-on`**: Specifies the runner environment (GitHub-hosted or self-hosted)
- **`if`**: Conditional execution based on expressions
- **`needs`**: Defines job dependencies
- **`strategy.matrix`**: Runs job multiple times with different configurations

### Steps

Steps are individual tasks within a job:

- **Action steps**: Use pre-built actions with `uses:`
- **Script steps**: Run shell commands with `run:`
- **Conditions**: Can have individual `if:` conditions

## Security-Relevant Workflow Features

### Context Variables

GitHub provides context information through special variables:

```yaml
steps:
  - name: Print context info
    run: |
      echo "Actor: ${{ github.actor }}"
      echo "Event: ${{ github.event_name }}"
      echo "PR Title: ${{ github.event.pull_request.title }}"
      echo "Comment: ${{ github.event.comment.body }}"
```

**Security Note**: Many context variables contain user-controlled data and can be exploited for injection attacks.

### Expressions and Functions

GitHub Actions supports expressions for dynamic behavior:

```yaml
if: contains(github.event.comment.body, '/deploy')
if: github.event.pull_request.head.repo.fork != true
if: startsWith(github.ref, 'refs/tags/')
```

### Permissions

Workflows can have different permission levels:

```yaml
permissions:
  contents: read
  issues: write
  pull-requests: write
  id-token: write      # For OIDC token generation
```

## Common Workflow Patterns

### CI/CD Pipeline

```yaml
name: CI/CD Pipeline
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
      - run: npm ci
      - run: npm test

  deploy:
    if: github.ref == 'refs/heads/main'
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to production
        run: ./deploy.sh
```

### Matrix Builds

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
    node-version: [16, 18, 20]
runs-on: ${{ matrix.os }}
steps:
  - uses: actions/setup-node@v4
    with:
      node-version: ${{ matrix.node-version }}
```

### Reusable Workflows

```yaml
name: Reusable Security Scan
on:
  workflow_call:
    inputs:
      config-path:
        required: true
        type: string
    secrets:
      token:
        required: true

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run security scan
        run: ./scan.sh ${{ inputs.config-path }}
        env:
          TOKEN: ${{ secrets.token }}
```

## Security Vulnerabilities in Workflows

### Pull Request Target Vulnerabilities (Pwn Requests)

The `pull_request_target` trigger is dangerous because it:

- Runs with the base repository's permissions
- Has access to secrets
- Can be triggered by external contributors

**Vulnerable Pattern**:
```yaml
on:
  pull_request_target:    # Dangerous trigger
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checking out untrusted code
      - run: ./build.sh     # Executing untrusted code
```

### Script Injection

User-controlled input in scripts can lead to command injection:

**Vulnerable Pattern**:
```yaml
on:
  issue_comment:
    types: [created]
jobs:
  process:
    if: contains(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Deploying to ${{ github.event.comment.body }}"  # Injection point
```

### Self-Hosted Runner Exposure

Self-hosted runners can expose sensitive environments:

**Risky Pattern**:
```yaml
on:
  pull_request:           # Accepts external PRs
jobs:
  build:
    runs-on: self-hosted  # Potentially sensitive environment
    steps:
      - uses: actions/checkout@v4
      - run: make build
```

## Workflow Analysis with Gato-X

### What Gato-X Analyzes

Gato-X examines workflows for:

1. **Dangerous Event Triggers**: `pull_request_target`, `issue_comment`, `workflow_run`
2. **Unsafe Checkouts**: Checking out untrusted code with elevated permissions
3. **Injection Vulnerabilities**: User input used in scripts without sanitization
4. **Self-Hosted Runner Usage**: Workflows that could expose internal infrastructure
5. **TOCTOU Conditions**: Time-of-check to time-of-use vulnerabilities
6. **Secrets Exposure**: Workflows that might leak secrets

### Workflow Risk Assessment

Gato-X evaluates workflows based on:

- **Event triggers and their security implications**
- **Runner types (GitHub-hosted vs self-hosted)**
- **Context variable usage**
- **Conditional logic and approval mechanisms**
- **Action usage and trust boundaries**

### Static Analysis Features

- **Expression Evaluation**: Analyzes GitHub expressions for unsafe patterns
- **Graph Building**: Creates dependency graphs of workflow steps and actions
- **Pattern Matching**: Identifies known vulnerable patterns
- **Context Flow**: Tracks how user input flows through workflows

## Best Practices for Secure Workflows

### Use Appropriate Triggers

```yaml
# Safer for external contributions
on:
  pull_request:           # Instead of pull_request_target
    branches: [ main ]

# Add approval requirements for sensitive workflows
on:
  pull_request_target:
    types: [ labeled ]    # Require manual labeling
```

### Validate and Sanitize Input

```yaml
# Bad - Direct injection
run: echo "Hello ${{ github.event.comment.body }}"

# Better - Controlled input
env:
  COMMENT: ${{ github.event.comment.body }}
run: |
  if [[ "$COMMENT" =~ ^/deploy[[:space:]]+[a-zA-Z0-9_-]+$ ]]; then
    echo "Valid deployment command"
  else
    echo "Invalid command format"
    exit 1
  fi
```

### Use Least Privilege

```yaml
permissions:
  contents: read          # Minimal permissions
  issues: write          # Only what's needed
```

### Secure Self-Hosted Runners

```yaml
on:
  pull_request:
    types: [ labeled ]    # Require approval
jobs:
  build:
    if: contains(github.event.label.name, 'safe-to-test')
    runs-on: self-hosted
```

## Workflow File Locations

Gato-X scans for workflows in standard locations:

- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`

It also considers:

- **Default branch workflows**: Primary security analysis target
- **Non-default branch workflows**: Secondary analysis (with `--deep-dive`)
- **Disabled workflows**: Still analyzed for potential vulnerabilities

## Advanced Workflow Features

### Composite Actions

Workflows can call composite actions that contain multiple steps:

```yaml
# .github/actions/setup/action.yml
name: 'Setup Environment'
description: 'Setup common environment'
runs:
  using: 'composite'
  steps:
    - run: echo "Setting up..."
      shell: bash
```

### Environments and Protection Rules

```yaml
jobs:
  deploy:
    environment: production  # Can have protection rules
    runs-on: ubuntu-latest
```

### OIDC Integration

```yaml
permissions:
  id-token: write
steps:
  - name: Configure AWS credentials
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
      aws-region: us-east-1
```

## Related Gato-X Features

- **[Enumerate Command](../command-reference/enumerate.md)**: Analyze workflows for vulnerabilities
- **[Attack Command](../command-reference/attack.md)**: Exploit identified vulnerabilities
- **[Search Command](../command-reference/search.md)**: Find repositories with specific workflow patterns
- **[Vulnerability Types](../advanced/vulnerabilities.md)**: Detailed vulnerability explanations

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [BlackHat 2024 Presentation](https://github.com/user-attachments/files/16575912/BH2024_SH_Runners_v8.pdf) - "Self-Hosted Runners: The Achilles Heel of GitHub Actions"