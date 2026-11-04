import {
    EMBEDS,
    FORM_PROVIDERS,
    FORM_PROCESSORS,
    isTrackingCookie,
    matchTracker,
    SESSION_COOKIE_HINTS,
    type Tracker,
} from "./trackers.ts";
import type {
    Confidence,
    Finding,
    Grade,
    ScanReport,
    Severity,
    ThirdPartyDomain,
} from "../types.ts";

// Signals in, report out; no browser, no I/O for testability.

export interface FormSignal {
    action: string;
    method: string;
    fields: string[];
}

export interface CookieSignal {
    name: string;
    domain: string;
    secure: boolean;
    httpOnly: boolean;
}

export interface Signals {
    finalUrl: string;
    servedOverHttp: boolean;
    /** The http:// variant of the host answered with a page instead of redirecting to HTTPS. */
    httpAnswers: boolean;
    title: string;
    requests: string[];
    cookies: CookieSignal[];
    headers: Record<string, string>;
    forms: FormSignal[];
    iframes: string[];
    privacyLinks: { text: string; href: string }[];
    cmpBanner: boolean;
}

const HEALTH_TERMS = [
    "addiction",
    "substance",
    "alcohol",
    "drug",
    "detox",
    "rehab",
    "overdose",
    "opioid",
    "relapse",
    "sober",
    "sobriety",
    "diagnosis",
    "symptom",
    "treatment",
    "therapy",
    "counseling",
    "mental health",
    "depression",
    "anxiety",
    "bipolar",
    "schizophrenia",
    "ptsd",
    "trauma",
    "medication",
    "insurance",
    "member id",
    "policy",
    "diagnosed",
    "patient",
    "dob",
    "date of birth",
    "birth",
];

const PII_TERMS = [
    "name",
    "email",
    "e-mail",
    "phone",
    "tel",
    "address",
    "zip",
    "postal",
    "message",
    "comments",
];

const CLINICAL_URL_TERMS = [
    "addiction",
    "rehab",
    "detox",
    "substance",
    "overdose",
    "opioid",
    "alcohol",
    "mental-health",
    "mentalhealth",
    "depression",
    "anxiety",
    "bipolar",
    "schizophrenia",
    "ptsd",
    "trauma",
    "therapy",
    "treatment",
    "counseling",
    "sober",
    "sobriety",
    "recovery",
    "crisis",
    "suicide",
];

const SEVERITY_ORDER: Record<Severity, number> = { High: 0, Medium: 1, Low: 2 };

function cut(text: string, max = 140): string {
    return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

function slug(text: string): string {
    return text
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
}

// Same-site by registrable-domain suffix; exact enough for evidence lists,
// wrong only for exotic public-suffix cases (e.g. co.uk subdomains).
// NOTE: suffix heuristic, swap for a PSL lookup if false positives show up.
function sameSite(a: string, b: string): boolean {
    const x = a.toLowerCase().replace(/^\./, "");
    const y = b.toLowerCase().replace(/^\./, "");
    return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

function termMatch(haystack: string, terms: string[]): string[] {
    const lower = haystack.toLowerCase();
    return terms.filter((term) =>
        new RegExp(`\\b${term.replace(/[-]/g, "[- ]")}`).test(lower)
    );
}

function finding(
    id: string,
    severity: Severity,
    confidence: Confidence,
    category: Finding["category"],
    title: string,
    evidence: string,
    hipaaRisk: string,
    recommendation: string
): Finding {
    return {
        id,
        severity,
        confidence,
        category,
        title,
        evidence,
        hipaaRisk,
        recommendation,
    };
}

const TRACKER_RISK: Record<Tracker["category"], string> = {
    "session recorder":
        "Session recorders capture everything a visitor types and does on the page, including messages about mental health or substance use, and send it all to a third-party vendor. On a treatment-center site that data is protected health information.",
    "ad pixel":
        "Advertising pixels send the visitor's page views, and often a cross-site identifier, to an advertising platform. If the visitor arrived from an ad about treatment, the platform learns that this person sought addiction or mental-health care.",
    analytics:
        "Analytics tools record page views tied to persistent identifiers. On its own this is lower risk, but combined with treatment-related page addresses it can reveal who sought care and for what.",
    "tag manager":
        "A tag manager is a container that can load any tracking script without code changes. Even if nothing harmful runs today, anything can be added later. Either way, a third party learns about every visit.",
    "chat widget":
        "Live-chat conversations on a treatment site often include disclosures about a person's condition or substance use. That content flows through a third-party vendor that is unlikely to have a business associate agreement.",
};

const TRACKER_FIX: Record<Tracker["category"], string> = {
    "session recorder":
        "Remove the session-recording tool, or sign a business associate agreement with the vendor and restrict it to non-clinical pages.",
    "ad pixel":
        "Remove the pixel. Advertising on treatment content is risky under HIPAA, and the safe default is to send nothing.",
    analytics:
        "Sign a business associate agreement, configure IP anonymization, and never send form or URL details into the analytics tool.",
    "tag manager":
        "Audit every tag inside the container, remove the ones that serve tracking to advertisers or recorders, and gate the rest behind consent.",
    "chat widget":
        "Sign a business associate agreement with the vendor, or move confidential conversations to a HIPAA-compliant channel.",
};

export function evaluate(s: Signals): ScanReport {
    const findings: Finding[] = [];
    const siteHost = new URL(s.finalUrl).hostname;
    const urlForLeakCheck = s.finalUrl.toLowerCase();
    const H: Record<string, string> = Object.fromEntries(
        Object.entries(s.headers).map(([k, v]) => [k.toLowerCase(), v])
    );

    // Third-party requests, deduped by vendor where known.
    const trackerHits = new Map<
        string,
        { tracker: Tracker; count: number; example: string }
    >();
    const hostCounts = new Map<string, number>();
    for (const request of s.requests) {
        const tracker = matchTracker(request);
        if (tracker) {
            const hit = trackerHits.get(tracker.vendor) ?? {
                tracker,
                count: 0,
                example: request,
            };
            hit.count += 1;
            trackerHits.set(tracker.vendor, hit);
        }
        try {
            const host = new URL(request).hostname;
            if (host && !sameSite(host, siteHost)) {
                hostCounts.set(host, (hostCounts.get(host) ?? 0) + 1);
            }
        } catch {
            // Unparseable request URL; nothing to attribute.
        }
    }

    // Area 1: trackers firing before any consent.
    for (const { tracker, count, example } of trackerHits.values()) {
        const severity: Severity =
            tracker.category === "session recorder" || tracker.category === "ad pixel"
                ? "High"
                : "Medium";
        findings.push(
            finding(
                `tracker-${slug(tracker.vendor)}`,
                severity,
                "verified",
                "Unconsented Tracking",
                `${tracker.vendor} (${tracker.category}) fires before any consent`,
                `${count} request${count === 1 ? "" : "s"} on page load, e.g. ${cut(example)}`,
                TRACKER_RISK[tracker.category],
                TRACKER_FIX[tracker.category]
            )
        );
    }

    // Area 1: pre-consent tracking cookies.
    const trackingCookies = s.cookies.filter((c) => isTrackingCookie(c.name));
    if (trackingCookies.length > 0) {
        findings.push(
            finding(
                "tracking-cookies",
                "High",
                "verified",
                "Unconsented Tracking",
                "Tracking cookies set before any visitor interaction",
                `Cookies observed on load: ${trackingCookies.map((c) => c.name).join(", ")}`,
                "These identifiers persist across visits and are shared with advertising and analytics vendors. Setting them before consent ignores the visitor's choice and, on a treatment site, links browsing behavior to a device.",
                "Configure the consent management platform to block these cookies until the visitor opts in, or remove the scripts that set them."
            )
        );
    }

    // Area 1: a consent banner that does not actually block anything.
    if (s.cmpBanner && trackerHits.size > 0) {
        findings.push(
            finding(
                "ineffective-banner",
                "High",
                "verified",
                "Unconsented Tracking",
                "Consent banner is present but does not block tracking",
                `A consent banner is on the page, yet ${trackerHits.size} tracking vendor${trackerHits.size === 1 ? "" : "s"} (${[...trackerHits.keys()].join(", ")}) still fired on load, before any visitor choice.`,
                "A banner that does not actually prevent tracking does not provide consent. The data flows exactly as it would with no banner at all.",
                "Configure the platform for genuine opt-in: trackers must not fire until the visitor accepts. Verify with a fresh browser session."
            )
        );
    }

    // Area 2: classify forms by what they collect. Cookie-consent forms are
    // the CMP's own UI, not patient data collection, and are excluded.
    const phiForms = s.forms
        .map((form) => {
            const fieldText = form.fields.join(" \n ");
            const health = termMatch(fieldText, HEALTH_TERMS);
            const pii = termMatch(fieldText, PII_TERMS);
            const freeText = form.fields.some((f) => f.startsWith("textarea"));
            return { ...form, health, pii, freeText };
        })
        .filter(
            (form) =>
                (form.health.length > 0 || form.pii.length > 0) &&
                !/cookie|consent/i.test(form.fields.join(" "))
        );

    // Area 2: PHI/PII collection.
    phiForms.forEach((form, i) => {
        const isHealth = form.health.length > 0;
        const matched = [...form.health, ...form.pii];
        const shown = [...new Set(form.fields)].slice(0, 6);
        findings.push(
            finding(
                `form-phi-${i}`,
                isHealth ? "High" : "Medium",
                "inferred",
                "Form & PHI Leakage",
                isHealth
                    ? "Form collects health-related details"
                    : "Form collects personal details",
                `Fields observed: ${shown.map((f) => cut(f, 60)).join("; ")}. Matched terms: ${matched.join(", ")}.${form.freeText ? " Includes a free-text field." : ""}`,
                isHealth
                    ? `A form asking about insurance, diagnosis, or substance use creates protected health information the moment a visitor starts typing.${form.freeText ? " The free-text field is where visitors most often describe their situation in their own words. That content is PHI, and it is the easiest thing for a third-party script or processor to capture." : ""} If that data is not sent and stored under HIPAA controls, the site is handling PHI without compliance.`
                    : `Personal details such as name, email, and phone tied to a treatment website's contact form can reveal that a person is seeking care.${form.freeText ? " The form also has a free-text field where visitors may describe their situation. On a treatment site that disclosure is protected health information." : ""}`,
                isHealth
                    ? "Ensure the form submits to a HIPAA-compliant endpoint with a signed business associate agreement, uses POST over HTTPS, and never pipes entries into analytics or advertising tools."
                    : "Use POST over HTTPS to a first-party or BAA-covered endpoint, and keep tracking scripts off pages with forms."
            )
        );

        // Area 2: transport risks for this form.
        const issues: string[] = [];
        try {
            if (form.action) {
                const action = new URL(form.action, s.finalUrl);
                if (action.protocol === "http:") {
                    issues.push(`submits over plain HTTP (${cut(action.toString())})`);
                }
                if (!sameSite(action.hostname, siteHost)) {
                    issues.push(`submits to a third-party domain (${action.hostname})`);
                }
            }
        } catch {
            issues.push(`has an unparseable action URL (${cut(form.action)})`);
        }
        if (form.method === "get") {
            issues.push(
                "submits via GET, putting field values into the page URL and server/analytics logs"
            );
        }
        if (issues.length > 0) {
            findings.push(
                finding(
                    `form-transport-${i}`,
                    "High",
                    "verified",
                    "Form & PHI Leakage",
                    "Form data transmission is not HIPAA-safe",
                    `Form ${i + 1} ${issues.join("; ")}.`,
                    "GET submissions put form answers into the page URL itself. Browsers, server logs, and any analytics tool watching requests keep copies of URLs. On an intake form those answers may cover diagnosis, insurance, or substance use. Plain HTTP sends them unencrypted, and third-party form handlers receive PHI with no business associate agreement.",
                    'Use method="post" with an HTTPS action on the same domain (or a vendor with a signed business associate agreement), and verify the endpoint preserves that method.'
                )
            );
        }

        // Area 2: destination cannot be confirmed without submitting.
        const hasClearAction =
            form.action !== "" && form.action !== "#" && !form.action.startsWith("#");
        if (!hasClearAction && form.method !== "get") {
            findings.push(
                finding(
                    `form-destination-${i}`,
                    "Low",
                    "unverifiable",
                    "Form & PHI Leakage",
                    "Form destination could not be verified",
                    `Form ${i + 1} declares no submit endpoint (no action attribute). Most such forms submit via JavaScript to a destination chosen in code.`,
                    "The scan never submits forms on sites it does not own, so it cannot observe where entries actually go. JavaScript-submitted forms often post to external CRMs and marketing platforms. That is a common and serious PHI leak, and this scan can neither confirm nor rule it out.",
                    "Ask the site owner or developer where this form sends data, and confirm that endpoint (and any CRM or marketing automation tool behind it) is covered by a signed business associate agreement."
                )
            );
        }
    });

    // Area 2: tracking tools on pages with PHI forms.
    if (phiForms.length > 0 && trackerHits.size > 0) {
        const severe = [...trackerHits.values()].filter(
            ({ tracker }) =>
                tracker.category === "session recorder" ||
                tracker.category === "ad pixel" ||
                tracker.category === "chat widget"
        );
        const vendors =
            severe.length > 0
                ? severe.map(({ tracker }) => tracker.vendor)
                : [...trackerHits.keys()];
        const severity: Severity = severe.length > 0 ? "High" : "Medium";
        findings.push(
            finding(
                "form-tracker-colocation",
                severity,
                "verified",
                "Form & PHI Leakage",
                "Tracking tools load on the same page as a patient form",
                `${vendors.join(", ")} active on a page containing ${phiForms.length} form${phiForms.length === 1 ? "" : "s"} collecting personal or health details.`,
                "Tracking and chat scripts on an intake page can capture keystrokes and form interactions, including what a visitor types about themselves, and send that context to third parties.",
                "Remove all third-party scripts from pages with intake or contact forms, or load them only after consent and never on clinical or intake routes."
            )
        );
    }

    // Area 2: third-party form processors observed on the page.
    if (phiForms.length > 0) {
        const processors = [
            ...new Set(
                FORM_PROCESSORS.filter((p) =>
                    s.requests.some((r) => r.includes(p.match))
                ).map((p) => p.vendor)
            ),
        ];
        if (processors.length > 0) {
            findings.push(
                finding(
                    "form-processor",
                    "Medium",
                    "inferred",
                    "Form & PHI Leakage",
                    "Form submissions appear to be handled by a third-party processor",
                    `${processors.join(", ")} script${processors.length === 1 ? "" : "s"} observed loading on the same page as form${phiForms.length === 1 ? "" : "s"} collecting personal or health details.`,
                    "Marketing and CRM form processors receive every entry the visitor types. Unless the vendor is covered by a business associate agreement, those details are PHI sent to an unmanaged third party. The scan infers this from the vendor's scripts being present; it cannot see the actual submission.",
                    "Verify which processor each form uses and whether a business associate agreement is in place; if not, move the form to a compliant endpoint."
                )
            );
        }
    }

    // Area 2: third-party embedded forms.
    const embeddedForms = s.iframes
        .map((src) => {
            const provider = FORM_PROVIDERS.find((p) =>
                src.toLowerCase().includes(p.domain)
            );
            return provider ? { provider, src } : undefined;
        })
        .filter(
            (v): v is { provider: (typeof FORM_PROVIDERS)[number]; src: string } =>
                v !== undefined
        );
    if (embeddedForms.length > 0) {
        findings.push(
            finding(
                "embedded-forms",
                "Medium",
                "verified",
                "Form & PHI Leakage",
                "Form is embedded from a third-party provider",
                embeddedForms
                    .map(({ provider, src }) => `${provider.vendor}: ${cut(src)}`)
                    .join("; "),
                "Entries typed into a third-party-hosted form go straight to that vendor. Unless the provider signs a business associate agreement, the submitted details, names and health concerns included, are PHI sent to an unmanaged third party.",
                "Confirm a business associate agreement with the provider, or self-host the form on the site's own domain."
            )
        );
    }

    // Area 3: clinical terms visible in the page address.
    let pathAndQuery = urlForLeakCheck;
    try {
        const url = new URL(urlForLeakCheck);
        pathAndQuery = `${url.pathname}${url.search}`;
    } catch {
        // Keep the raw string; term matching still works.
    }
    const clinicalTerms = termMatch(pathAndQuery, CLINICAL_URL_TERMS);
    if (clinicalTerms.length > 0) {
        findings.push(
            finding(
                "clinical-url",
                trackerHits.size > 0 ? "High" : "Medium",
                "verified",
                "Infrastructure & Policy",
                "The page address contains condition or treatment terms",
                `URL path/query contains: ${clinicalTerms.join(", ")} (${cut(pathAndQuery, 80)})`,
                trackerHits.size > 0
                    ? "The page address is shared with every third party the page contacts, through the HTTP Referer header and the page's own JavaScript. Combined with the trackers observed here, outside companies learn that this visitor browsed treatment-related content."
                    : "Page addresses travel in browser history, server logs, and the HTTP Referer header to any external resource the page loads.",
                "Move treatment content to neutral URLs, set a strict Referrer-Policy, and never put condition terms in query strings."
            )
        );
    }

    // Area 3: transport and security headers.
    const headerKeys = Object.keys(H);
    const missing = [
        s.servedOverHttp ||
        s.httpAnswers ||
        headerKeys.includes("strict-transport-security")
            ? undefined
            : "Strict-Transport-Security (forces HTTPS on future visits)",
        headerKeys.includes("content-security-policy")
            ? undefined
            : "Content-Security-Policy (limits which scripts can run)",
        headerKeys.includes("referrer-policy")
            ? undefined
            : "Referrer-Policy (limits URL leakage to third parties; absent means the browser default applies)",
        headerKeys.includes("x-frame-options") ||
        (H["content-security-policy"]?.includes("frame-ancestors") ?? false)
            ? undefined
            : "X-Frame-Options or frame-ancestors (prevents clickjacking)",
    ].filter((v): v is string => v !== undefined);
    const referrerPolicy = H["referrer-policy"] ?? "";
    const unsafeReferrer = /unsafe-url|no-referrer-when-downgrade/.test(referrerPolicy)
        ? referrerPolicy
        : undefined;
    if (s.servedOverHttp) {
        findings.push(
            finding(
                "insecure-transport",
                "High",
                "verified",
                "Infrastructure & Policy",
                "Page loads over unencrypted HTTP",
                `The site served this page over plain HTTP (${cut(s.finalUrl, 80)}).`,
                "Anything a visitor does on an unencrypted page can be read or changed by others on the network path, including every detail typed into a form.",
                "Serve every page over HTTPS and redirect HTTP traffic automatically."
            )
        );
    } else if (s.httpAnswers) {
        findings.push(
            finding(
                "http-open",
                "High",
                "verified",
                "Infrastructure & Policy",
                "The unencrypted HTTP version of this site answers directly",
                `http://${siteHost} served a page instead of redirecting to HTTPS, so visitors and search engines can reach the site without encryption.`,
                "A visitor who follows an http:// link from an email, an ad, or an old directory listing gets an unencrypted session. Anything typed into a form on that page travels in the clear and can be modified along the way.",
                "Redirect every http:// request to HTTPS with a permanent (301) redirect, and add Strict-Transport-Security."
            )
        );
    }
    if (missing.length > 0 || unsafeReferrer) {
        findings.push(
            finding(
                "security-headers",
                "Medium",
                "verified",
                "Infrastructure & Policy",
                "Key security headers are missing or weak",
                [
                    missing.length > 0 && `Missing: ${missing.join("; ")}.`,
                    unsafeReferrer &&
                        `Referrer-Policy is set to "${unsafeReferrer}", which sends the full page address, treatment terms included, to third parties.`,
                ]
                    .filter(Boolean)
                    .join(" "),
                "Missing headers leave browsers open to content injection, clickjacking, and URL leakage. A permissive Referrer-Policy also leaks the page address, treatment terms included, to every third party on the page.",
                "Add the missing headers at the web server or CDN edge; each takes one configuration line. Set Referrer-Policy to strict-origin-when-cross-origin or stricter."
            )
        );
    }

    // Area 3: cookies lacking Secure/HttpOnly.
    const insecureCookies = s.cookies.filter(
        (c) =>
            (!c.secure || !c.httpOnly) &&
            !isTrackingCookie(c.name) &&
            SESSION_COOKIE_HINTS.some((hint) => c.name.toLowerCase().includes(hint))
    );
    if (insecureCookies.length > 0) {
        findings.push(
            finding(
                "insecure-cookies",
                "Medium",
                "verified",
                "Infrastructure & Policy",
                "Cookies lack Secure or HttpOnly flags",
                insecureCookies
                    .map(
                        (c) =>
                            `${c.name} [${!c.secure ? "no Secure " : ""}${!c.httpOnly ? "no HttpOnly" : ""}]`
                    )
                    .join(", "),
                "A cookie without the Secure flag can travel over plain HTTP. Without HttpOnly, any script on the page can read it, third-party trackers included. A stolen session cookie is account takeover.",
                "Set the Secure and HttpOnly flags on every session cookie, and add SameSite=Lax or Strict."
            )
        );
    }

    // Area 3: third-party embeds.
    const embeds = s.iframes
        .map((src) => {
            const embed = EMBEDS.find((e) => src.toLowerCase().includes(e.domain));
            return embed ? { embed, src } : undefined;
        })
        .filter(
            (v): v is { embed: (typeof EMBEDS)[number]; src: string } => v !== undefined
        );
    if (embeds.length > 0) {
        findings.push(
            finding(
                "third-party-embeds",
                "Medium",
                "verified",
                "Infrastructure & Policy",
                "Third-party content is embedded on the page",
                embeds
                    .map(({ embed, src }) => `${embed.vendor}: ${cut(src, 80)}`)
                    .join("; "),
                "Embedded media and scheduling tools receive the visitor's IP address and page URL on load, treatment terms included, and set their own cookies.",
                embeds.map(({ embed }) => embed.note).join(" ")
            )
        );
    }

    // Area 3: privacy policy / notice of privacy practices.
    if (s.privacyLinks.length === 0) {
        findings.push(
            finding(
                "no-privacy-policy",
                "Medium",
                "verified",
                "Infrastructure & Policy",
                "No privacy policy link found on the page",
                "No link with privacy, HIPAA, or notice-of-privacy-practices wording was found on this page.",
                "A covered entity must provide a notice of privacy practices. If visitors cannot find it, that is both a compliance gap and a trust signal.",
                "Link a privacy policy and notice of privacy practices from every page footer."
            )
        );
    }

    // Score, grade, and plain-language summary. Unverifiable findings are
    // informational: they describe this tool's blind spot, not the site's
    // behavior, and do not deduct points.
    const scoreable = findings.filter((f) => f.confidence !== "unverifiable");
    const high = scoreable.filter((f) => f.severity === "High").length;
    const medium = scoreable.filter((f) => f.severity === "Medium").length;
    const low = scoreable.filter((f) => f.severity === "Low").length;
    const unverifiable = findings.length - scoreable.length;
    const score = Math.max(0, 100 - high * 25 - medium * 10 - low * 5);
    const grade: Grade =
        score >= 90
            ? "A"
            : score >= 80
              ? "B"
              : score >= 70
                ? "C"
                : score >= 60
                  ? "D"
                  : "F";
    const riskLevel =
        grade === "A" || grade === "B" ? "Low" : grade === "C" ? "Medium" : "High";

    const thirdPartyDomains: ThirdPartyDomain[] = [...hostCounts.entries()]
        .map(([domain, requestCount]) => {
            const hit = [...trackerHits.values()].find(({ tracker }) =>
                tracker.domains.some((d) => {
                    const entryHost = d.split("/")[0];
                    return sameSite(domain, entryHost);
                })
            );
            return {
                domain,
                category: hit
                    ? `${hit.tracker.vendor} (${hit.tracker.category})`
                    : "other",
                requestCount,
            };
        })
        .sort((a, b) => b.requestCount - a.requestCount);

    const summary = buildSummary(s, {
        trackerVendors: [...trackerHits.values()],
        phiForms,
        clinicalTerms,
        missingHeaders: missing,
        unsafeReferrer,
        servedOverHttp: s.servedOverHttp,
        httpAnswers: s.httpAnswers,
        high,
        medium,
        unverifiable,
    });

    findings.sort((a, b) => {
        const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
        if (sev !== 0) return sev;
        // Within a severity, verified evidence reads first; unverifiable last.
        const conf: Record<Confidence, number> = {
            verified: 0,
            inferred: 1,
            unverifiable: 2,
        };
        return conf[a.confidence] - conf[b.confidence];
    });

    return {
        targetUrl: s.finalUrl,
        scannedAt: new Date().toISOString(),
        grade,
        riskLevel,
        summary,
        thirdPartyDomains,
        findings,
    };
}

function buildSummary(
    s: Signals,
    context: {
        trackerVendors: { tracker: Tracker; count: number }[];
        phiForms: (FormSignal & { health: string[]; pii: string[]; freeText: boolean })[];
        clinicalTerms: string[];
        missingHeaders: string[];
        unsafeReferrer?: string;
        servedOverHttp: boolean;
        httpAnswers: boolean;
        high: number;
        medium: number;
        unverifiable: number;
    }
): string {
    const {
        trackerVendors,
        phiForms,
        clinicalTerms,
        missingHeaders,
        unsafeReferrer,
        servedOverHttp,
        httpAnswers,
        high,
        medium,
        unverifiable,
    } = context;
    if (high === 0 && medium === 0) {
        const unverifiableNote =
            unverifiable > 0
                ? ` There ${unverifiable === 1 ? "is 1 item" : `are ${unverifiable} items`} the tool could not verify without submitting forms.`
                : "";
        return `We scanned ${s.finalUrl} and found no tracking tools, risky forms, or missing security basics.${unverifiableNote} This is an automated technical review, not legal advice.`;
    }

    const parts: string[] = [];
    const byCategory = (category: Tracker["category"]) =>
        trackerVendors.filter(({ tracker }) => tracker.category === category);
    const recorders = byCategory("session recorder").map(({ tracker }) => tracker.vendor);
    const pixels = byCategory("ad pixel").map(({ tracker }) => tracker.vendor);
    const chats = byCategory("chat widget").map(({ tracker }) => tracker.vendor);

    if (trackerVendors.length > 0) {
        const named = [
            recorders.length > 0 && `session-recording tools (${recorders.join(", ")})`,
            pixels.length > 0 && `advertising pixels (${pixels.join(", ")})`,
            chats.length > 0 && `chat widgets (${chats.join(", ")})`,
            trackerVendors.length > recorders.length + pixels.length + chats.length &&
                "analytics and tag-manager tools",
        ].filter(Boolean);
        parts.push(
            `This page sends data to ${trackerVendors.length} outside tracking vendor${trackerVendors.length === 1 ? "" : "s"} the moment it loads, before any visitor consent: ${named.join(" and ")}.`
        );
    }
    if (phiForms.length > 0) {
        const health = phiForms.some((f) => f.health.length > 0);
        parts.push(
            `The page includes a form collecting ${health ? "health-related" : "personal"} details${trackerVendors.length > 0 ? ", and tracking scripts load alongside it" : ""}.`
        );
    }
    if (clinicalTerms.length > 0) {
        parts.push(
            "The page address itself contains condition or treatment terms, which third parties can observe."
        );
    }
    if (servedOverHttp) {
        parts.push("The page is served over unencrypted HTTP.");
    } else if (httpAnswers) {
        parts.push(
            "The unencrypted HTTP version of the site answers instead of redirecting to HTTPS."
        );
    } else if (missingHeaders.length > 0 || unsafeReferrer) {
        parts.push("Basic security headers are missing or weakened.");
    }
    parts.push(
        `Overall: ${high + medium} finding${high + medium === 1 ? "" : "s"}: ${high} high-severity${medium ? ` and ${medium} medium` : ""}${unverifiable ? `, plus ${unverifiable} that could not be verified without submitting forms` : ""}. This is an automated technical review, not legal advice or a compliance certification.`
    );
    return parts.join(" ");
}
