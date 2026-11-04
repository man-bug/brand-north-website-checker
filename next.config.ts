import type { NextConfig } from "next";

const nextConfig: NextConfig = {
    cacheComponents: true,
    // Chromium's brotli binary must not pass through the server bundler.
    serverExternalPackages: ["puppeteer-core", "@sparticuz/chromium"],
    // @sparticuz/chromium loads its binaries via fs at runtime, which the
    // file tracer cannot see; ship them explicitly. Both routes that launch
    // the browser need them.
    outputFileTracingIncludes: {
        "/api/scan": ["./node_modules/@sparticuz/chromium/bin/**"],
        "/api/report/pdf": ["./node_modules/@sparticuz/chromium/bin/**"],
    },
    partialPrefetching: true,
    reactCompiler: true,
    turbopack: {
        rules: {
            "*.css": {
                loaders: ["@tailwindcss/turbopack"],
                as: "*.css",
            },
        },
    },
};

export default nextConfig;
