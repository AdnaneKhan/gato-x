# Enumerate Command

The enumerate command analyzes GitHub repositories for exploitable vulnerabilities in GitHub Actions workflows. It performs static analysis of workflow files and can analyze workflow run logs to identify self-hosted runners.

## Basic Usage

```bash
gato-x enumerate [options]
# or
gato-x enum [options]
# or
gato-x e [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target an organization to enumerate for self-hosted runners |
| `--repository`, `-r` | Target a single repository in org/repo format |
| `--repositories`, `-R` | A text file containing repositories in org/repo format |
| `--commit`, `-c` | Analyze a specific commit SHA (40 hex chars) in the target repository |
| `--self-enumeration`, `-s` | Enumerate the configured token's access and all repositories or organizations the user has write access to |
| `--validate`, `-v` | Validate if the token is valid and print organization memberships |
| `--output-yaml`, `-o` | Directory to save gathered workflow yml files to |
| `--skip-runners`, `-sr` | Do NOT enumerate runners via run-log analysis |
| `--machine` | Run with a GitHub App token for single repository enumeration |
| `--ignore-workflow-run` | Ignore the `workflow_run` trigger when enumerating repositories |
| `--output-json`, `-oJ` | Save enumeration output to JSON file |
| `--deep-dive`, `-dd` | Perform deep dive static analysis, including analyzing non-default branches |
| `--cache-restore-file` | Path to JSON file containing saved reusable action files |
| `--cache-save-file` | Path to JSON file to save cache to after executing |

## Examples

### Enumerate a single repository

```bash
gato-x enumerate -r MyOrg/MyRepo
```

### Analyze a specific commit in a repository

```bash
gato-x e -r MyOrg/MyRepo --commit 9659fdc7ba35a9eba00c183bccc67083239383e8
```

> **Note:** The `--commit` option requires a full 40-character SHA hash and must be used with the `--repository` option. Gato-X will "pretend" the commit is present on the default branch for purposes of
identifying vulnerabilities.

### Enumerate multiple repositories from a file

```bash
gato-x e -R repositories.txt
```

### Self-enumeration to identify accessible resources

```bash
gato-x e -s
```

### Validate a GitHub token

```bash
gato-x e -v
```

### Enumerate an organization with deep dive analysis

```bash
gato-x e -t MyOrganization -dd
```

### Save results to JSON for further analysis

```bash
gato-x e -R repositories.txt -oJ results.json
```

## Understanding the Output

The enumerate command performs several types of analysis:

1. **Reachability Analysis** - Determines if user-controlled inputs can reach sensitive parts of workflows
2. **Cross-Repository Analysis** - Analyzes workflows and reusable actions across repositories
3. **If Statement Simulation** - Parses and simulates conditional statements in workflows
4. **Gate Check Detection** - Identifies permission checks and other security controls
5. **Source-Sink Analysis** - Tracks variables from user inputs to sensitive operations

Results are presented with confidence ratings to help prioritize findings.

### Single Commit Analysis

When using the `--commit` option, gato-x analyzes the workflow files as they existed at the specified commit. This is useful for:

- **Historical Analysis** - Understanding vulnerabilities that existed at a specific point in time
- **Incident Response** - Analyzing the security posture at the time of a security incident
- **Regression Testing** - Verifying that security fixes were effective at a particular commit
- **Compliance Auditing** - Demonstrating security analysis for specific software releases

The commit analysis assumes the specified SHA represents the latest commit on the default branch and analyzes all workflow files present at that point in the repository's history.
