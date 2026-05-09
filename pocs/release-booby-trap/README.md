# Release Booby Trap PoC

**Canonical reference:** https://github.com/Dev11940518/release-bomb-demo

## Technique Overview

The **Release Booby Trap** is a GitHub Actions attack technique where an
attacker plants a malicious workflow at an *orphan commit* (not on any branch)
and creates a release whose `target_commitish` points to it.  The release
sits dormant in the Releases tab looking like an innocuous `untagged-XXXXXXXX`.
When any non-bot actor interacts with the release — rename it, delete it,
upload an asset, toggle draft — the planted workflow fires, bypassing
GitHub's loop-prevention.

## Attack Chain (from the demo repo)

### 1. Plant (planter.yml)

A workflow with `permissions: contents: write` (typical for release-please,
semantic-release, auto-merge bots, any CI that commits back) executes:

1. **Builds an orphan commit** via the Git Data API:
   - Creates a blob containing the bomb workflow YAML (see `bomb.yml`)
   - Tree-splices it into `.github/workflows/<rand>.yml`
   - Creates an orphan commit from the spliced tree

2. **Creates a release** via the Releases API:
   - Creates a *draft* release with `target_commitish=main` (clean,
     passes GitHub's 2023 workflow-scope check)
   - **PATCHes** `target_commitish` to the orphan SHA — the PATCH
     bypasses the creation-time scope check
   - PATCHes `draft=false` to publish

### 2. Dormant

GitHub's loop-prevention suppresses the immediate workflow dispatch
because the publishing actor is `GITHUB_TOKEN`.  The release sits
dormant in the Releases tab as `untagged-XXXXXXXX`.

### 3. Detonation (bomb.yml)

The planted workflow triggers on `release: [edited, deleted]`.
When ANY non-bot actor interacts with the release:

- Maintainer renames the release via the web UI
- Maintainer uploads or deletes an asset
- Maintainer toggles draft / prerelease
- A release-management bot (release-please etc.) using a PAT processes it

Each interaction fires `release: edited`.  Loop prevention does NOT apply
because the actor is not `GITHUB_TOKEN`.  The planted workflow at the
orphan SHA executes with whatever permissions the attacker declared
(e.g., `id-token: write` for OIDC abuse).

### 4. What makes this a "booby trap"

The release is a *trap* — it looks like a normal (though suspicious)
untagged release.  A maintainer's natural response is to investigate
and delete it.  That act of cleanup **is** the trigger.

## Files

| File | Description |
|------|-------------|
| `planter.yml` | The planter workflow — creates the orphan commit + release |
| `bomb.yml` | The bomb payload — the YAML tree-spliced into the orphan commit |

## Detection with Gato-X

Gato-X detects the **bomb pattern**: a workflow triggered on `release`
whose event types include `edited` or `deleted`.  These are strong
indicators of a planted booby-trap payload because normal release
workflows trigger on `published`, not `edited`/`deleted`.

```bash
gato-x scan --repo owner/repo
```

## Mitigation

1. **Audit workflows with `contents: write`** — especially those that
   run on `issue_comment`, `pull_request_target`, or accept
   untrusted input.

2. **Use fine-grained permissions** — scope `GITHUB_TOKEN` to the
   minimum required per job, not per workflow.

3. **Monitor the Releases tab** for unexpected `untagged-XXXX` releases.

4. **Never manually interact with suspicious releases** — use the
   GitHub API or a trusted admin workflow that verifies the release
   before touching it.

5. **Enable branch protection** including "Require status checks before
   merging" — this doesn't prevent the attack but makes it harder to
   get `contents: write` in the first place.

## Citation

- Dev11940518, ["release-bomb-demo"](https://github.com/Dev11940518/release-bomb-demo) (GitHub, 2025)
