import { launchBrowser } from "@/lib/browser";
import { evaluate } from "@/lib/rules/evaluate";
import type { ScanReport } from "@/lib/types";

const PAGE_LOAD_TIMEOUT_MS = 15_000;
const MAX_REQUESTS = 400;

export async function scan(targetUrl: string): Promise<ScanReport> {
    const browser = await launchBrowser();
    try {
        const page = await browser.newPage();

        const requests: string[] = [];
        page.on("request", (request) => {
            if (requests.length < MAX_REQUESTS) {
                requests.push(request.url());
            }
        });

        const response = await page.goto(targetUrl, {
            timeout: PAGE_LOAD_TIMEOUT_MS,
            waitUntil: "networkidle2",
        });

        const [title, cookies, dom] = await Promise.all([
            page.title(),
            page.browserContext().cookies(),
            page.evaluate(() => {
                const formField = (el: Element) => {
                    const label =
                        el.closest(".form-field, .field, label")?.textContent ??
                        el.getAttribute("aria-label") ??
                        "";
                    // Leading tag name lets evaluation spot free-text fields.
                    return [
                        el.tagName.toLowerCase(),
                        el.getAttribute("name"),
                        el.getAttribute("id"),
                        el.getAttribute("placeholder"),
                        label.trim(),
                    ]
                        .filter(Boolean)
                        .join(" | ");
                };
                return {
                    forms: [...document.querySelectorAll("form")].map((form) => ({
                        action: form.getAttribute("action") ?? "",
                        method: (form.getAttribute("method") ?? "").toLowerCase(),
                        fields: [...form.querySelectorAll("input, textarea, select")]
                            .map(formField)
                            .filter(Boolean),
                    })),
                    iframes: [...document.querySelectorAll("iframe")]
                        .map((f) => f.getAttribute("src") ?? "")
                        .filter(Boolean),
                    privacyLinks: [...document.querySelectorAll("a[href]")]
                        .map((a) => ({
                            text: (a.textContent ?? "").trim(),
                            href: a.getAttribute("href") ?? "",
                        }))
                        .filter(
                            (a) =>
                                /privac|hipaa|notice of privacy/i.test(a.text) ||
                                /privac|hipaa/i.test(a.href)
                        ),
                    cmpBanner:
                        [
                            "#onetrust-banner-sdk",
                            "#onetrust-consent-sdk",
                            "#CybotCookiebotDialog",
                            ".osano-cm-window",
                            "#cookie-law-info-bar",
                            "[id*='cookie-banner']",
                            "[id*='cookie-consent']",
                            "[class*='cookie-consent']",
                            "[class*='cookie-banner']",
                            "[class*='CookieConsent']",
                            "[data-testid*='consent']",
                            "[aria-label*='cookie' i]",
                        ].some((sel) => {
                            try {
                                return document.querySelector(sel) !== null;
                            } catch {
                                return false;
                            }
                        }) ||
                        /we use cookies|accept all cookies|manage (cookie )?preferences|cookie settings/i.test(
                            document.body.textContent?.slice(0, 20000) ?? ""
                        ),
                };
            }),
        ]);

        // Footer content and consent-gated widgets often lazy-render; a
        // scroll pass coaxes them into the DOM before the snapshot.
        await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
        await new Promise((resolve) => setTimeout(resolve, 800));
        await page.evaluate(() => window.scrollTo(0, 0));

        const finalUrl = response?.url() ?? targetUrl;

        // Does the unencrypted variant answer directly instead of redirecting
        // to HTTPS? Plain fetch, no browser; any failure means "no evidence".
        let httpAnswers = false;
        if (new URL(finalUrl).protocol === "https:") {
            try {
                const probe = await fetch(`http://${new URL(finalUrl).host}/`, {
                    redirect: "manual",
                    signal: AbortSignal.timeout(5000),
                });
                httpAnswers = probe.status === 200;
            } catch {
                // Refused, timed out, or blocked. HTTPS-only as far as we know.
            }
        }

        return evaluate({
            finalUrl,
            servedOverHttp: new URL(finalUrl).protocol === "http:",
            httpAnswers,
            title,
            requests,
            cookies: cookies.map((c) => ({
                name: c.name,
                domain: c.domain,
                secure: c.secure,
                httpOnly: c.httpOnly ?? false,
            })),
            headers: response?.headers() ?? {},
            forms: dom.forms,
            iframes: dom.iframes,
            privacyLinks: dom.privacyLinks,
            cmpBanner: dom.cmpBanner,
        });
    } finally {
        await browser.close();
    }
}
