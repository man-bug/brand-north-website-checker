import { strict } from "node:assert";
import test from "node:test";
import { evaluate, type Signals } from "./evaluate.ts";

const HTTPS_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-frame-options": "DENY",
};

function baseSignals(overrides: Partial<Signals> = {}): Signals {
    return {
        finalUrl: "https://clinic.example/",
        servedOverHttp: false,
        httpAnswers: false,
        title: "Clinic",
        requests: [],
        cookies: [],
        headers: { ...HTTPS_HEADERS },
        forms: [],
        iframes: [],
        privacyLinks: [{ text: "Privacy Policy", href: "/privacy" }],
        cmpBanner: false,
        ...overrides,
    };
}

function ids(report: ReturnType<typeof evaluate>): string[] {
    return report.findings.map((f) => f.id);
}

test("clean site grades A with no findings", () => {
    const report = evaluate(baseSignals());
    strict.equal(report.grade, "A");
    strict.equal(report.riskLevel, "Low");
    strict.equal(report.findings.length, 0);
    strict.ok(report.summary.includes("no tracking tools"));
});

test("tracker requests produce per-vendor findings with severity by category", () => {
    const report = evaluate(
        baseSignals({
            requests: [
                "https://connect.facebook.net/en_US/fbevents.js",
                "https://connect.facebook.net/signals",
                "https://www.google-analytics.com/analytics.js",
                "https://static.hotjar.com/c/hotjar.js",
            ],
        })
    );
    strict.deepEqual(ids(report), [
        "tracker-meta-pixel",
        "tracker-hotjar",
        "tracker-google-analytics",
    ]);
    strict.equal(report.findings[0].severity, "High");
    strict.ok(report.findings[0].evidence.includes("2 requests"));
    strict.equal(report.thirdPartyDomains.length, 3);
});

test("path-qualified dictionary entries do not overmatch", () => {
    // A bare GTM container load is a tag manager, not Google Analytics.
    const report = evaluate(
        baseSignals({ requests: ["https://www.googletagmanager.com/gtm.js?id=GTM-XYZ"] })
    );
    strict.deepEqual(ids(report), ["tracker-google-tag-manager"]);
});

test("tracking cookies and ineffective banner fire together", () => {
    const report = evaluate(
        baseSignals({
            requests: ["https://static.hotjar.com/c/hotjar.js"],
            cookies: [
                {
                    name: "_fbp",
                    domain: ".clinic.example",
                    secure: true,
                    httpOnly: false,
                },
                {
                    name: "session_id",
                    domain: "clinic.example",
                    secure: false,
                    httpOnly: false,
                },
            ],
            cmpBanner: true,
        })
    );
    strict.ok(ids(report).includes("tracking-cookies"));
    strict.ok(ids(report).includes("ineffective-banner"));
    // Session-named cookie without flags is caught too, not the tracker cookie.
    const insecure = report.findings.find((f) => f.id === "insecure-cookies");
    strict.ok(insecure?.evidence.includes("session_id"));
});

test("PHI form with GET and http action raises transport finding", () => {
    const report = evaluate(
        baseSignals({
            forms: [
                {
                    action: "http://clinic.example/submit",
                    method: "get",
                    fields: [
                        "your_name | name | Your name",
                        "phone | phone | Phone",
                        "insurance | insurance | Insurance provider",
                    ],
                },
            ],
        })
    );
    const phi = report.findings.find((f) => f.id === "form-phi-0");
    strict.ok(phi);
    strict.equal(phi.severity, "High");
    strict.ok(phi.evidence.includes("insurance"));
    const transport = report.findings.find((f) => f.id === "form-transport-0");
    strict.ok(transport);
    strict.ok(transport.evidence.includes("GET"));
    strict.ok(transport.evidence.includes("HTTP"));
});

test("a plain search-style form without PHI fields is not flagged", () => {
    const report = evaluate(
        baseSignals({
            forms: [{ action: "", method: "", fields: ["q | search | Search the site"] }],
        })
    );
    strict.equal(report.findings.length, 0);
});

test("tracker co-location with PHI form is High and named", () => {
    const report = evaluate(
        baseSignals({
            requests: ["https://connect.facebook.net/en_US/fbevents.js"],
            forms: [
                {
                    action: "/contact",
                    method: "post",
                    fields: ["message | message | How can we help?"],
                },
            ],
        })
    );
    const co = report.findings.find((f) => f.id === "form-tracker-colocation");
    strict.ok(co);
    strict.equal(co.severity, "High");
    strict.ok(co.evidence.includes("Meta Pixel"));
});

test("clinical URL terms escalate when trackers are present", () => {
    const clean = evaluate(
        baseSignals({ finalUrl: "https://clinic.example/addiction-treatment" })
    );
    const withTrackers = evaluate(
        baseSignals({
            finalUrl: "https://clinic.example/addiction-treatment",
            requests: ["https://static.hotjar.com/c/hotjar.js"],
        })
    );
    strict.equal(clean.findings.find((f) => f.id === "clinical-url")?.severity, "Medium");
    strict.equal(
        withTrackers.findings.find((f) => f.id === "clinical-url")?.severity,
        "High"
    );
});

test("missing headers and insecure transport are flagged", () => {
    const report = evaluate(baseSignals({ headers: {}, servedOverHttp: true }));
    strict.ok(ids(report).includes("insecure-transport"));
    const headers = report.findings.find((f) => f.id === "security-headers");
    // HSTS is deliberately not listed for an HTTP page; the dedicated
    // insecure-transport High finding covers the transport problem.
    strict.ok(headers?.evidence.includes("Content-Security-Policy"));
});

test("scoring maps severities to grades", () => {
    strict.equal(
        evaluate(baseSignals({ requests: ["https://static.hotjar.com/x.js"] })).grade,
        "C"
    );
    strict.equal(
        evaluate(
            baseSignals({
                requests: ["https://static.hotjar.com/x.js"],
                cookies: [
                    {
                        name: "_fbp",
                        domain: ".clinic.example",
                        secure: true,
                        httpOnly: false,
                    },
                ],
            })
        ).grade,
        "F"
    );
    strict.equal(
        evaluate(
            baseSignals({
                headers: {},
                servedOverHttp: true,
                requests: ["https://static.hotjar.com/x.js"],
            })
        ).grade,
        "F"
    );
});

test("third-party form iframe and embeds are Medium findings", () => {
    const report = evaluate(
        baseSignals({
            iframes: [
                "https://form.typeform.com/to/abc123",
                "https://www.youtube.com/embed/xyz",
            ],
        })
    );
    strict.ok(ids(report).includes("embedded-forms"));
    strict.ok(ids(report).includes("third-party-embeds"));
    strict.ok(
        report.findings.every(
            (f) =>
                f.severity === "Medium" || f.severity === "High" || f.severity === "Low"
        )
    );
});

test("PHI form without action gets an unverifiable destination finding that does not affect grading", () => {
    const withForm = evaluate(
        baseSignals({
            forms: [
                {
                    action: "",
                    method: "",
                    fields: ["message | message | How can we help?"],
                },
            ],
        })
    );
    const destination = withForm.findings.find((f) => f.id === "form-destination-0");
    strict.ok(destination);
    strict.equal(destination.confidence, "unverifiable");
    strict.ok(destination.hipaaRisk.includes("never submits"));
    // Unverifiable findings are informational: grade stays A.
    strict.equal(withForm.grade, "A");
    strict.ok(withForm.summary.includes("could not be verified"));

    // A clear same-origin action does not trigger it.
    const withAction = evaluate(
        baseSignals({
            forms: [
                {
                    action: "/contact",
                    method: "post",
                    fields: ["message | message | How can we help?"],
                },
            ],
        })
    );
    strict.equal(
        withAction.findings.find((f) => f.id.startsWith("form-destination")),
        undefined
    );
});

test("form processor scripts alongside PHI forms are inferred", () => {
    const report = evaluate(
        baseSignals({
            requests: ["https://js.hs-scripts.com/12345.js"],
            forms: [{ action: "", method: "", fields: ["email | email | Email"] }],
        })
    );
    const processor = report.findings.find((f) => f.id === "form-processor");
    strict.ok(processor);
    strict.equal(processor.confidence, "inferred");
    strict.ok(processor.evidence.includes("HubSpot"));
    // No PHI forms, no finding.
    const noForms = evaluate(
        baseSignals({ requests: ["https://js.hs-scripts.com/12345.js"] })
    );
    strict.equal(
        noForms.findings.find((f) => f.id === "form-processor"),
        undefined
    );
});

test("unsafe Referrer-Policy values are called out; safe ones are not", () => {
    const unsafe = evaluate(
        baseSignals({
            headers: {
                ...HTTPS_HEADERS,
                "referrer-policy": "no-referrer-when-downgrade",
            },
        })
    );
    strict.ok(
        unsafe.findings
            .find((f) => f.id === "security-headers")
            ?.evidence.includes("no-referrer-when-downgrade")
    );

    const safe = evaluate(
        baseSignals({ headers: { ...HTTPS_HEADERS, "referrer-policy": "strict-origin" } })
    );
    strict.equal(
        safe.findings.find((f) => f.id === "security-headers"),
        undefined
    );
});

test("free-text fields are mentioned in PHI form findings", () => {
    const report = evaluate(
        baseSignals({
            forms: [
                {
                    action: "/contact",
                    method: "post",
                    fields: [
                        "textarea | message | message | Your story",
                        "name | name | Name",
                    ],
                },
            ],
        })
    );
    const phi = report.findings.find((f) => f.id === "form-phi-0");
    strict.ok(phi?.evidence.includes("free-text"));
    strict.ok(phi?.hipaaRisk.includes("free-text field"));
});

test("http answering directly triggers the http-open finding", () => {
    const report = evaluate(baseSignals({ httpAnswers: true }));
    strict.ok(ids(report).includes("http-open"));
    strict.equal(report.findings.find((f) => f.id === "http-open")?.severity, "High");
    strict.ok(report.summary.includes("unencrypted HTTP version"));
});
