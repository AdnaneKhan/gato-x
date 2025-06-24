# Using Gato-X for Continuous Scanning

Gato-X has features that make it useful for continuously scanning thousands of repositories daily in production environments.

* Reusable Action Caching
* Webhook Notifications
* Repository Discovery and Search Features
* Tunable Configuration

## Reusable Action Caching

Gato-X performs analysis of all referenced reusable actions (even cross repository!) to identify vulnerabilities present within action.yml files.

This is an involved process because Gato-X will make one API request for each referenced reusable action. When scanning a large amount of repositories, this can quickly lead to rate limiting. To mitigate this, Gato-X implements intelligent caching:

- **In-Memory Cache**: Actions are cached during a single run to avoid redundant API calls
- **Cross-Repository Analysis**: The same reusable action used across multiple repositories is only fetched once
- **Reference-Aware Caching**: Actions are cached by repository, path, and reference (branch/tag/commit)

This caching mechanism significantly reduces API usage and improves scan performance when analyzing large numbers of repositories.

## Webhook Notifications

Gato-X supports sending notifications to Slack webhooks when it detects vulnerabilities committed within the last 24 hours. This feature is particularly useful for continuous monitoring scenarios where you want immediate alerts about new security issues.

### Configuration

To configure webhook notifications, you need to modify the `gatox/configuration/notifications.json` file:

```json
{
    "name": "NOTIFICATIONS",
    "entries": {
        "SLACK_WEBHOOKS": [
            "https://hooks.slack.com/services/YOUR/WEBHOOK/URL1",
            "https://hooks.slack.com/services/YOUR/WEBHOOK/URL2"
        ]
    }
}
```

### Features

- **Multiple Webhooks**: Configure multiple Slack webhook URLs for redundancy or different channels
- **Automatic Retry**: The webhook sender includes retry logic with exponential backoff
- **Structured Messages**: Notifications include detailed vulnerability information in JSON format
- **Recent Vulnerability Filter**: Only notifications for vulnerabilities in commits from the last 24 hours are sent

### Implementation Details

The webhook notification system:
- Uses asynchronous HTTP requests to avoid blocking the main scanning process
- Implements connection pooling for efficient network usage
- Includes a 10-second timeout for webhook requests
- Retries failed requests up to 3 times with 1-second delays
- Supports HTTP/2 for improved performance

## Repository Discovery and Search Features

Gato-X provides powerful search capabilities to identify candidate repositories for continuous scanning, making it easy to discover repositories that may contain vulnerabilities.

### GitHub Code Search API

Use GitHub's native search API to find repositories within specific organizations:

```bash
# Search for repositories in a specific organization
gato-x search -t MyOrganization -oT org_candidates.txt

# Search with custom queries for specific vulnerability patterns
gato-x s -q 'org:MyOrg pull_request_target file:.github/workflows/ lang:yaml' -oT pr_target_repos.txt
```

### Sourcegraph Integration

For large-scale scanning, Sourcegraph provides more powerful search capabilities:

```bash
# Search for potentially vulnerable workflows across GitHub
gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|issues:)/ file:.github/workflows/ lang:yaml' -oT candidates.txt
```

Sourcegraph search features:
- **Higher Limits**: Can return up to 75,000 results compared to GitHub's more restrictive limits
- **Advanced Regex**: Supports complex regular expressions for pattern matching
- **Cross-Platform**: Can search beyond just GitHub repositories
- **Real-Time Results**: Streaming search results for faster processing

### Effective Search Patterns

Here are proven search patterns for finding different types of vulnerabilities:

#### Pwn Request Vulnerabilities
```bash
# GitHub API
gato-x s -q 'pull_request_target file:.github/workflows/ lang:yaml' -oT pwn_candidates.txt

# Sourcegraph (recommended for scale)
gato-x s -sg -q 'pull_request_target file:.github/workflows/ lang:yaml' -oT pwn_candidates.txt
```

#### Actions Injection Vulnerabilities
```bash
# Issue comment triggers
gato-x s -q 'issue_comment file:.github/workflows/ lang:yaml' -oT injection_candidates.txt

# Multiple trigger types
gato-x s -sg -q '/(issue_comment|issues)/ file:.github/workflows/ lang:yaml' -oT injection_candidates.txt
```

#### Self-Hosted Runner Usage
```bash
# Direct self-hosted references
gato-x s -q 'runs-on: self-hosted file:.github/workflows/ lang:yaml' -oT runner_candidates.txt

# Custom runner labels (excluding GitHub-hosted)
gato-x s -sg -q 'runs-on AND NOT /(ubuntu|windows|macos)/ file:.github/workflows/ lang:yaml' -oT custom_runners.txt
```

### Continuous Discovery Workflow

For production continuous scanning, implement this workflow:

1. **Daily Repository Discovery**:
   ```bash
   # Update candidate list daily
   gato-x s -sg -q 'count:75000 /(issue_comment|pull_request_target|workflow_dispatch)/ file:.github/workflows/ lang:yaml' -oT daily_candidates.txt
   ```

2. **Incremental Scanning**:
   ```bash
   # Compare with previous day's list to identify new repositories
   comm -13 yesterday_candidates.txt daily_candidates.txt > new_candidates.txt
   ```

3. **Targeted Enumeration**:
   ```bash
   # Scan new and updated repositories
   gato-x e -R new_candidates.txt -oJ daily_results.json
   ```

## Tunable Configuration

Gato-X provides several configuration options to optimize performance for continuous scanning:

### API Rate Limiting
- **Concurrent Requests**: Adjust the semaphore limits for API calls
- **Request Batching**: GraphQL queries are automatically batched for efficiency
- **Intelligent Backoff**: Automatic handling of GitHub's rate limits with appropriate delays

### Scanning Depth
- **Deep Dive Mode** (`-dd`): Enables analysis of non-default branches but requires Git
- **Skip Runners** (default): Avoids expensive run log analysis for faster scanning
- **Workflow Run Analysis**: Can be disabled for speed when runner enumeration isn't needed

### Output Optimization
- **JSON Output** (`-oJ`): Structured output for automated processing
- **Text Output** (`-oT`): Human-readable output for manual review
- **Incremental Results**: Process results as they become available

### Example Production Configuration

```bash
# Fast scanning for continuous monitoring
gato-x e -R candidates.txt --skip-runners -oJ results.json

# Comprehensive scanning (weekly deep dive)
gato-x e -R candidates.txt -dd -oJ comprehensive_results.json

# Organization-wide scanning with webhook notifications
gato-x e -t MyOrganization -oJ org_scan.json
```

## Best Practices for Continuous Scanning

1. **Stagger Scans**: Avoid hitting rate limits by spreading scans across time
2. **Result Deduplication**: Track previously identified vulnerabilities to avoid alert fatigue
3. **Incremental Processing**: Focus on new repositories and recent changes
4. **Monitoring**: Set up alerts for scan failures or unexpected API usage patterns
