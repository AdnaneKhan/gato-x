# Search Command

The search command allows you to find repositories with potential GitHub Actions vulnerabilities using GitHub's code search API or Sourcegraph.

## Basic Usage

```bash
gato-x search [options]
# or
gato-x s [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Organization to enumerate using GitHub code search |
| `--query`, `-q` | Pass a custom query to GitHub code search |
| `--sourcegraph`, `-sg` | Use Sourcegraph API to search for self-hosted runners |
| `--output-text`, `-oT` | Save enumeration output to text file |

## Examples

### Search an organization for potential vulnerabilities

```bash
gato-x search -t MyOrganization
```

### Use a custom search query with Sourcegraph

```bash
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml' -oT results.txt
```

### Search for specific workflow patterns

```bash
gato-x search -q 'org:MyOrganization pull_request_target file:.github/workflows/ lang:yaml'
```

## Effective Search Queries

Here are some effective search queries for finding potential vulnerabilities:

### Pwn Request Vulnerabilities

```
pull_request_target file:.github/workflows/ lang:yaml
```

### Actions Injection Vulnerabilities

```
issue_comment file:.github/workflows/ lang:yaml
```

### Self-Hosted Runners

```
runs-on: self-hosted file:.github/workflows/ lang:yaml
```

### TOCTOU Vulnerabilities

```
workflow_dispatch file:.github/workflows/ lang:yaml
```

## Output

The search command outputs a list of repositories that match the search criteria. This output can be saved to a file using the `-oT` option and then used as input for the enumerate command.
