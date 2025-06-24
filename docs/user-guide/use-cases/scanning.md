# Scanning for Vulnerabilities

This guide explains how to effectively use Gato-X to scan repositories for GitHub Actions vulnerabilities.

## Overview

Gato-X's scanning capabilities are designed to identify exploitable vulnerabilities in GitHub Actions workflows. The process typically involves two steps:

1. **Search**: Find repositories with potential vulnerabilities
2. **Enumerate**: Analyze those repositories to identify exploitable issues

## Step 1: Search for Candidate Repositories

### Using Sourcegraph (Recommended for Large-Scale Scanning)

Sourcegraph provides more powerful search capabilities and can handle larger result sets:

```bash
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml' -oT candidates.txt
```

This query searches for:
- Workflows that use potentially vulnerable event triggers
- Up to 75,000 results
- YAML files in the .github/workflows directory

### Using GitHub's Search API

For smaller scans or targeting specific organizations:

```bash
gato-x s -t MyOrganization -oT org_repos.txt
```

Or with a custom query:

```bash
gato-x s -q 'org:MyOrganization pull_request_target file:.github/workflows/ lang:yaml' -oT pr_target_repos.txt
```

## Step 2: Enumerate Repositories for Vulnerabilities

Once you have a list of candidate repositories, use the enumerate command to analyze them:

```bash
gato-x e -R candidates.txt -oJ results.json | tee scan_output.txt
```

This command:
- Processes all repositories from the candidates.txt file
- Saves structured results to results.json for further analysis
- Displays and saves the human-readable output to scan_output.txt

### Deep Dive Analysis

For more thorough analysis that includes non-default branches:

```bash
gato-x e -R candidates.txt -dd -oJ results.json | tee scan_output.txt
```

Note: Deep dive analysis requires Git to be installed and available in your PATH.

## Optimizing Large-Scale Scans

For scanning thousands of repositories efficiently:

### Use Caching

```bash
# First run - save cache
gato-x e -R batch1.txt --cache-save-file cache.json -oJ results1.json

# Subsequent runs - restore and update cache
gato-x e -R batch2.txt --cache-restore-file cache.json --cache-save-file cache.json -oJ results2.json
```

### Skip Runner Log Analysis

If you're only interested in code-level vulnerabilities and not self-hosted runners:

```bash
gato-x e -R candidates.txt -sr -oJ results.json
```

### Parallel Processing

For very large scans, you can split your candidate list into multiple files and run Gato-X in parallel:

```bash
# Terminal 1
gato-x e -R batch1.txt -oJ results1.json

# Terminal 2
gato-x e -R batch2.txt -oJ results2.json
```

## Analyzing Results

Gato-X provides detailed information about each finding, including:

- The type of vulnerability
- The workflow file and line number
- The event trigger and conditions
- A confidence rating

Focus on high-confidence findings first, as these are most likely to be exploitable.

## Next Steps

After identifying vulnerabilities:

1. Verify the findings manually to confirm they are exploitable
2. Follow responsible disclosure practices to report the issues
3. For your own repositories, implement fixes based on the findings
