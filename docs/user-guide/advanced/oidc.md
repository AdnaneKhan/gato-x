# OIDC Token Exchange

GitHub Actions can mint short-lived OpenID Connect (OIDC) tokens that workflows exchange with third-party services (AWS, GCP, Azure, npm, Vault, PyPI, sigstore, etc.) for cloud credentials or publish rights. When a user with `workflow` write access compromises a repository — or is the repository — Gato-X's `--oidc` attack mode mints those tokens on demand and exfiltrates them so they can be replayed against the trusting third party.

## How the Attack Works

`gato-x attack --oidc` pushes a workflow that:

1. Requests an OIDC token from `$ACTIONS_ID_TOKEN_REQUEST_URL` for the audience supplied via `--oidc-audience`.
2. Writes the JWT to an artifact (`oidc_token.txt`).
3. Optionally fans out across one or more GitHub Actions environments via a job matrix (`--environments`), so each environment-bound token (with its `sub` claim referencing that environment) is minted in a single run.

Once the workflow completes, Gato-X downloads the artifact, prints the raw JWT, and decodes the claims (`iss`, `aud`, `sub`, `repository`, `environment`, `ref`, ...). Use these claims to determine which trust policies on the third party will accept the token.

## Token Lifetime

**The minted JWT is valid for ~5 minutes from issuance, regardless of whether the GitHub Actions workflow run is still running, has completed, or has been deleted.**

This is the property that makes the attack interesting: the token is a bearer credential issued by `token.actions.githubusercontent.com` and signed with GitHub's OIDC signing key. Once minted, its validity is determined entirely by its `iat` / `exp` claims and the third party's trust policy — not by whether the originating workflow is still active. Deleting the workflow run (`-d`) after exfiltration removes the audit trail in the Actions tab but does **not** revoke the token.

Practical consequences:

- After exfiltration you have roughly 5 minutes to redeem the token at the target service (`sts:AssumeRoleWithWebIdentity`, `npm publish --provenance`, etc.). Plan the follow-on action before launching the attack.
- If the target third party caches the resulting credential (e.g. AWS returns 1-hour STS session credentials), the downstream credential outlives the OIDC token. Trade up immediately.
- Re-running the attack mints a fresh token — there is no per-token rate limit beyond the normal Actions concurrency.

## Environments and the `sub` Claim

Many trust policies pin on the `sub` claim, which by default encodes `repo:OWNER/REPO:ref:refs/heads/BRANCH` but changes shape when the job binds to an environment (`repo:OWNER/REPO:environment:ENV_NAME`). Use `--environments` / `-ev` to mint one token per environment in a single workflow run; each artifact is uploaded under a sanitized name and Gato-X labels the printed token with the original environment name.

Environment names containing characters that GitHub disallows in artifact names (`" : < > | * ? \ / \r \n`) are automatically sanitized for the artifact name only — the workflow still binds to the real environment, so the resulting `sub` claim is unchanged.

## Required Permissions

- A token with `repo` + `workflow` scopes (classic PAT) **or** a fine-grained PAT with `contents:write` + `workflows:write` on the target repo.
- The repository must allow `id-token: write` permission for workflows. Public repos on the free plan support this by default; private/internal repos depend on org policy.

## Example

```bash
GH_TOKEN=$(gh auth token) gato-x a --oidc \
  -oa "npm:registry.npmjs.org" \
  -t MyOrg/MyRepo \
  --file-name release \
  -d \
  -ev "NPM | CLI" "Production"
```

This mints two tokens — one bound to the `NPM | CLI` environment, one to `Production` — both with audience `npm:registry.npmjs.org`, and deletes the workflow run after exfiltration.

## Defensive Notes

- Trust policies on third parties should pin `repository`, `repository_owner`, and ideally `environment` and `ref` — never just `repository_owner` alone.
- Require environment protection rules (required reviewers, branch restrictions) on any environment whose `sub` claim grants production access.
- Treat any actor who can push a workflow file as someone who can mint every OIDC token the workflow is allowed to request. Limit `workflow` scope on PATs accordingly.
