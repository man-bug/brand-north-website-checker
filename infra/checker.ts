// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="../.sst/platform/config.d.ts" />

// The scanner lives in the Next.js server function itself (an API route),
// not a dedicated Lambda: no CORS, no second URL, no extra IAM surface.
// Memory drives vCPU allocation on Lambda, so 3008 MB buys the headless
// Chromium scan the CPU it needs.

export function checker() {
    const site = new sst.aws.Nextjs("WebsiteChecker", {
        // SST would otherwise auto-detect Next 16 and pick OpenNext 3.9.14,
        // which predates Next 16.4; the 4.x line carries the compatibility
        // fixes.
        openNextVersion: "4.1.12",

        // install marks these esbuild-external and installs them at deploy
        // time, keeping the @sparticuz/chromium brotli binary intact.
        server: {
            memory: "3008 MB",
            // Also becomes the edge origin read timeout via the router KV
            // metadata (ssr-site.ts -> router.ts CF_ROUTER_INJECTION); the
            // distribution's placeholder originReadTimeout is unused.
            timeout: "55 seconds",
            install: ["puppeteer-core", "@sparticuz/chromium"],
        },

        protection: "oac-with-edge-signing",
    });

    return {
        url: site.url,
    };
}
