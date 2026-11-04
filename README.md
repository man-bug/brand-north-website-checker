# Brand North Website Checker

Paste a URL, get a report on the HIPAA and PHI privacy risks the site creates for its visitors: third-party trackers that fire before consent, forms that leak patient details, and missing security basics.

Live tool: https://dlb8qvsouqxdp.cloudfront.net

This is an automated technical review. It is not legal advice and not a HIPAA compliance certification.

## What it detects

A headless Chromium on the server loads the submitted page and observes three things before any visitor interaction: every network request that fires (with full URLs), every cookie that gets set, and the response headers. It also snapshots the DOM: forms and their fields, iframes, consent banners, and privacy-policy links. An evaluation step turns those signals into findings.

The rules cover three areas:

- **Unconsented tracking.** Requests and cookies matched against a curated dictionary of ad pixels, session recorders, analytics, tag managers, and chat widgets. A consent banner that is present while trackers still fire gets its own finding.
- **Forms and PHI.** Fields classified by keyword matching on names, placeholders, and labels; transport checks on the declared action and method (GET, plain HTTP, third-party endpoints); tracker and chat scripts co-located on form pages; third-party embedded forms and form-processor scripts.
- **Infrastructure and policy.** Clinical terms in the page address that third parties can observe via the Referer header; missing or weak security headers; cookies without Secure/HttpOnly; third-party embeds; missing privacy-policy links.

Each finding states how it was established: **Direct evidence** (a request, cookie, header, or attribute we observed), **Inferred** (a heuristic interpretation, like keyword-classified form fields), or **Could not verify** (things a scanner cannot check without submitting forms, which it never does on sites it does not own). Unverifiable findings are informational and do not affect the grade. The grade itself is a weighted deduction: 25 points per high-severity finding, 10 per medium, 5 per low, floored at zero and mapped to A through F.

## Running locally

Requires Node 24 and pnpm.

```sh
pnpm install
pnpm dev
```

Local scans launch system Chrome; the bundled Chromium only runs on Linux. `pnpm test` runs the unit checks (URL validation and the rule engine) with no browser and no network beyond DNS lookups.

## Deployment

The tool runs on AWS through [SST](https://sst.dev): one Lambda running the Next.js app (via OpenNext) behind a CloudFront distribution.

Why this setup: the scanner needs a real browser, which means a Node runtime with memory headroom (the function runs at 3008 MB, where Lambda allocates proportionally more CPU) and a generous timeout (55 seconds, which also becomes the CloudFront origin timeout). CloudFront gives TLS and caching at the edge, and origin access control with edge signing keeps the function URL from being invocable directly (CDN verification). The Chromium binary ships as a brotli-compressed package marked external to the bundler, with its runtime-loaded assets forced into the Lambda bundle through `outputFileTracingIncludes`.

To redeploy, with AWS credentials configured:

```sh
pnpm install
pnpm deploy --stage prod
```

`pnpm remove --stage prod` tears everything down.

Pushes to main deploy automatically through GitHub Actions; pull requests get lint, typecheck, and tests. The auth model and IAM scoping are documented in `docs/ci.md`.

## Architecture

A scan flows through:

1. **UI** (`src/components/scan-form.tsx`) posts the URL to `POST /api/scan`.
2. **Validation** (`src/lib/validate-url.ts`): scheme normalization, then DNS resolution of the host and rejection of private, loopback, link-local, and CGNAT ranges for both IPv4 and IPv6, including the AWS metadata address. A separate probe checks whether the unencrypted HTTP variant of the site answers instead of redirecting.
3. **Collection** (`src/lib/scanner.ts`): one browser pass gathers request URLs, cookies, response headers, and a DOM snapshot (forms with field descriptors, iframes, privacy links, consent-banner markers). Nothing interacts with the page.
4. **Evaluation** (`src/lib/rules/evaluate.ts`): a pure function from signals to findings, grade, and summary. No I/O, which makes it unit-testable against synthetic signals.
5. **Report**: JSON back to the UI, and `POST /api/report/pdf` renders a print template through the same browser stack for the PDF download.

## AI tools

Built with opencode as the coding-agent harness and GLM (via OpenRouter) as the model, routed from a US server so prompts and code stayed on US infrastructure. The agent debugged the Lambda Chromium bundle from CloudWatch logs, implemented the tracker list, wrote the copy, and audited the codebase for mistakes a few times. I made the product and scope decisions and reviewed every change.

## Not built, and known limits

- **Single page per scan.** The submitted URL only. Multi-page crawling (contact and intake pages especially) was cut for time; given more, I'd change the infrastructure to house multiple Lambdas, one for each URL parsed from a sitemap (if found) or a crawler (if no sitemap was found). Our 55s timeout would almost certainly cause this setup to fail consistently for large websites.
- **Curated tracker dictionary.** Trackers outside the list stay invisible. A generated list from DuckDuckGo's Tracker Radar dataset was planned but not shipped.
- **Form findings are keyword-based.** A field named "name" that is really a username is a false positive; an unlabeled field is a false negative. Declared form actions may not match actual submission behavior, and JavaScript-submitted forms get an explicit "could not be verified" finding.
- **Consent semantics are load-time.** Everything the scan observes fired before any interaction, which is the point, but consent management platforms are detected by DOM markers and banner text, not by executing their APIs.
- **Cookie and policy checks are heuristic.** Insecure-cookie findings use session-name patterns; the privacy-policy check judges only the submitted page, so a site whose footer says "Compliance & Policies" instead of "Privacy" will be reported as missing one even if a policy exists elsewhere.
- **The HTTP probe checks only the root path.**

## With one more week

Security and operations first, since a public tool that fetches arbitrary URLs is super abuse-prone: per-IP rate limiting, CloudFront WAF rules and Lambda concurrency caps, CI deploys with OIDC-scoped AWS roles, a custom domain with HSTS preload, and an automated refresh of the tracker list from DuckDuckGo's Tracker Radar (CC BY-NC-SA 4.0; attribution required for that data).

Then the feature work: multi-page scans with contact and intake page discovery under a hard scan deadline, CNAME resolution in the URL validator (it currently trusts A and AAAA records only, so an ALIAS-style DNS rebinding remains open), and passive form-endpoint verification through scripted non-submitting interactions.
