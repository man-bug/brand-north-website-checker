# CI authentication and pipelines

How pushes to main deploy this app, and how the AWS access is scoped. This account hosts other projects, so every grant is app-scoped by hand; the policy in `infra/ci-oidc.ts` is the auditable artifact.

## Auth model

GitHub Actions authenticates through OIDC role assumption. No secrets live in the repository: a run exchanges a GitHub-issued token for temporary AWS credentials. The single role, `github-website-checker-deploy`, is created by this repo's `ci` stage (`pnpm exec sst deploy --stage ci`) and carries `protect: true`, so removal takes a deliberate two-step change.

The trust condition pins the subject branch-exact:

```
repo:man-bug@136141397/brand-north-website-checker@1446140408:ref:refs/heads/main
```

The subject uses GitHub's immutable `owner@ID/repo@ID` format for repos created after 2026-07-15; slug-based subjects never match. Because the trust is branch-exact on main, fork pull requests cannot deploy: they never push to main.

## Permission scoping

| Grant                 | Scope                                                                                                                                                                        |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SST state             | `sst-state-mxhnetvbrttm` under `*/website-checker/*`; bucket listing is unconditioned (reveals key names only).                                                              |
| Function code         | `sst-asset-mxhnetvbrttm` under `assets/WebsiteChecker*`, the component-name prefix.                                                                                          |
| Site assets          | Buckets matching `website-*`. Lambda truncates the app name per resource (`website-c-`, `website-check-`, `website-checke-` observed), so the shared prefix, not the full app name, is the scoping floor. |
| IAM                  | Role lifecycle and PassRole on `role/website-*` only; managed-policy attach is conditioned on the AWSLambdaBasicExecutionRole ARN.                   |
| Compute and data     | Functions, tables, queues, and log groups under `website-*`, plus the unprefixed `WebsiteCheckerRevalidationEventsSubscriber*` (SST names it without the stage prefix). |
| Event source mappings | Account-wide; mapping ARNs are UUIDs.                                                                                                                                        |
| CloudFront            | Account-wide; distribution and policy ARNs are random IDs. The KV store grant is the same class, its ARNs are UUIDs and untaggable.                                          |
| SST bootstrap         | SSM `parameter/sst/bootstrap`, plus `GetParameter` on `parameter/sst/passphrase/website-checker/*`.                                                                          |

## Accepted risk

The deploy role holds `iam:CreateRole` and `iam:PutRolePolicy` on `website-check*` plus PassRole, so code executing inside `sst deploy` could escalate to account-admin by creating an unscoped role and invoking it. SST requires this grant surface to create function execution roles. The blast radius is bounded by the account being shared only with personal projects. Fix ladder, best first: a dedicated AWS account; then CloudTrail detection on `CreateRole` outside deploy windows.

## Workflows

- `deploy.yml`, push to main: install, OIDC, `sst deploy --stage prod`. Queued concurrency (never interrupt a half-deploy), 30-minute timeout, actions SHA-pinned.
- `ci.yml`, pull requests: lint, build, typecheck, tests. No AWS access, `contents: read` only. The two generated type sources (`sst install` for `.sst/platform`, `next build` for `.next/types`) run before typecheck.
- `.github/dependabot.yml`: weekly grouped minor/patch updates for npm and actions.

Verify the trust policy after changes:

```sh
aws iam get-role --role-name github-website-checker-deploy --query 'Role.AssumeRolePolicyDocument'
```
