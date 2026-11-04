// Known third-party trackers by hostname suffix. Each entry lists domains
// whose presence in observed requests identifies the vendor; matching is a
// hostname "ends with" check against these suffixes.
//
// NOTE: AI generated list, not exhaustive; unknown trackers are invisible to
// the tool. I would extend from CDP/duckduckgo/etc. tracker lists for the real
// application.

export type TrackerCategory =
    | "session recorder"
    | "ad pixel"
    | "analytics"
    | "tag manager"
    | "chat widget";

export interface Tracker {
    vendor: string;
    category: TrackerCategory;
    domains: string[];
}

export const TRACKERS: Tracker[] = [
    // Session recorders: keystrokes, mouse movement, scroll behavior.
    {
        vendor: "Hotjar",
        category: "session recorder",
        domains: ["hotjar.com", "hotjar.io"],
    },
    {
        vendor: "Microsoft Clarity",
        category: "session recorder",
        domains: ["clarity.ms"],
    },
    { vendor: "FullStory", category: "session recorder", domains: ["fullstory.com"] },
    {
        vendor: "LogRocket",
        category: "session recorder",
        domains: ["logrocket.com", "logrocket.io"],
    },
    { vendor: "Mouseflow", category: "session recorder", domains: ["mouseflow.com"] },
    { vendor: "Smartlook", category: "session recorder", domains: ["smartlook.com"] },
    { vendor: "Crazy Egg", category: "session recorder", domains: ["crazyegg.com"] },
    {
        vendor: "Lucky Orange",
        category: "session recorder",
        domains: ["luckyorange.com", "luckyorange.net"],
    },
    { vendor: "Inspectlet", category: "session recorder", domains: ["inspectlet.com"] },
    {
        vendor: "Glassbox",
        category: "session recorder",
        domains: ["glassbox.com", "glassboxdigital.com"],
    },
    {
        vendor: "Quantum Metric",
        category: "session recorder",
        domains: ["quantummetric.com"],
    },
    {
        vendor: "VWO",
        category: "session recorder",
        domains: ["vwo.com", "visualwebsiteoptimizer.com"],
    },

    // Ad pixels: visitor identity forwarded to advertising platforms.
    {
        vendor: "Meta Pixel",
        category: "ad pixel",
        domains: ["connect.facebook.net", "facebook.com/tr", "facebook.net"],
    },
    {
        vendor: "Google Ads",
        category: "ad pixel",
        domains: [
            "googleadservices.com",
            "doubleclick.net",
            "googlesyndication.com",
            "google.com/pagead",
        ],
    },
    {
        vendor: "TikTok Pixel",
        category: "ad pixel",
        domains: ["analytics.tiktok.com", "tiktok.com/i18n/pixel"],
    },
    {
        vendor: "LinkedIn Insight Tag",
        category: "ad pixel",
        domains: ["snap.licdn.com", "px.ads.linkedin.com"],
    },
    { vendor: "Microsoft/Bing Ads", category: "ad pixel", domains: ["bat.bing.com"] },
    {
        vendor: "X/Twitter Pixel",
        category: "ad pixel",
        domains: ["static.ads-twitter.com", "ads-twitter.com"],
    },
    { vendor: "Pinterest Tag", category: "ad pixel", domains: ["ct.pinterest.com"] },
    {
        vendor: "Snapchat Pixel",
        category: "ad pixel",
        domains: ["sc-static.net", "tr.snapchat.com"],
    },

    // Analytics: usage measurement, usually with persistent identifiers.
    {
        vendor: "Google Analytics",
        category: "analytics",
        domains: [
            "google-analytics.com",
            "analytics.google.com",
            "googletagmanager.com/gtag",
        ],
    },
    { vendor: "Matomo", category: "analytics", domains: ["matomo.cloud"] },
    {
        vendor: "Segment",
        category: "analytics",
        domains: ["segment.com", "segment.io", "cdn.segment.com"],
    },
    {
        vendor: "Heap",
        category: "analytics",
        domains: ["heap.io", "heapdata.com", "cdn.heapanalytics.com"],
    },
    {
        vendor: "Amplitude",
        category: "analytics",
        domains: ["amplitude.com", "api.amplitude.com", "cdn.amplitude.com"],
    },
    {
        vendor: "Mixpanel",
        category: "analytics",
        domains: ["mixpanel.com", "cdn.mxpnl.com"],
    },
    { vendor: "StatCounter", category: "analytics", domains: ["statcounter.com"] },

    // Tag managers: containers that can load any of the above dynamically.
    {
        vendor: "Google Tag Manager",
        category: "tag manager",
        domains: ["googletagmanager.com/gtm.js", "googletagmanager.com/gtag/js"],
    },
    {
        vendor: "Tealium",
        category: "tag manager",
        domains: ["tiqcdn.com", "tealiumiq.com"],
    },
    {
        vendor: "Adobe Launch",
        category: "tag manager",
        domains: ["adobedtm.com", "demdex.net"],
    },

    // Chat widgets: conversations on a treatment site are PHI-adjacent.
    {
        vendor: "Intercom",
        category: "chat widget",
        domains: ["intercom.io", "intercomcdn.com"],
    },
    {
        vendor: "Zendesk",
        category: "chat widget",
        domains: ["zendesk.com", "zdassets.com"],
    },
    { vendor: "Drift", category: "chat widget", domains: ["drift.com", "driftt.com"] },
    { vendor: "Tawk.to", category: "chat widget", domains: ["tawk.to"] },
    {
        vendor: "LiveChat",
        category: "chat widget",
        domains: ["livechatinc.com", "livechat.com"],
    },
    { vendor: "Podium", category: "chat widget", domains: ["podium.com"] },
    { vendor: "Crisp", category: "chat widget", domains: ["crisp.chat"] },
];

// Pre-consent tracking cookie name prefixes/names seen in the wild.
export const TRACKING_COOKIES = [
    "_ga",
    "_gid",
    "_gat",
    "_gcl_au",
    "_fbp",
    "_fbc",
    "_hj",
    "_clck",
    "_clsk",
    "_uetvid",
    "_uetsid",
    "_tt_",
    "li_sugr",
    "bcookie",
    "personalization_id",
    "IDE",
    "IDESTS",
    "fr",
];

// Cookie name fragments that indicate a session or login cookie worth
// flagging when it lacks Secure/HttpOnly.
export const SESSION_COOKIE_HINTS = [
    "sess",
    "session",
    "auth",
    "token",
    "login",
    "sid",
    "csrf",
    "wp-log",
    "logged_in",
];

// Scripts that indicate a form is processed by a third-party vendor; the
// match is a plain substring test against full request URLs.
export const FORM_PROCESSORS = [
    { vendor: "HubSpot", match: "hs-scripts.com" },
    { vendor: "HubSpot", match: "hsforms.net" },
    { vendor: "Marketo", match: "munchkin.marketo.com" },
    { vendor: "Pardot", match: "pardot.com" },
    { vendor: "Gravity Forms", match: "/wp-content/plugins/gravityforms/" },
    { vendor: "WPForms", match: "/wp-content/plugins/wpforms/" },
    { vendor: "Contact Form 7", match: "/wp-content/plugins/contact-form-7/" },
    { vendor: "Salesforce", match: "webto.salesforce.com" },
];

// Third-party providers that host embedded forms.
export const FORM_PROVIDERS = [
    { vendor: "Typeform", domain: "typeform.com" },
    { vendor: "Jotform", domain: "jotform.com" },
    { vendor: "Google Forms", domain: "docs.google.com/forms" },
    { vendor: "HubSpot", domain: "hsforms.com" },
    { vendor: "Wufoo", domain: "wufoo.com" },
    { vendor: "Calendly", domain: "calendly.com" },
    { vendor: "Formstack", domain: "formstack.com" },
    { vendor: "Gravity Forms (hosted)", domain: "gravityforms.com" },
];

// Domain suffixes for third-party embeds that receive the visitor IP and
// page URL on load.
export const EMBEDS = [
    {
        vendor: "YouTube video",
        domain: "youtube.com/embed",
        note: "Use youtube-nocookie.com embeds and click-to-play.",
    },
    {
        vendor: "Google Maps",
        domain: "google.com/maps",
        note: "Use a static map image or a click-to-load consent gate.",
    },
    {
        vendor: "Vimeo video",
        domain: "player.vimeo.com",
        note: "Gate the player behind consent.",
    },
    {
        vendor: "Calendly scheduling",
        domain: "calendly.com",
        note: "Loads visitor data into Calendly without a BAA by default.",
    },
];

// Cookie-consent management platform DOM markers. Presence plus observed
// pre-consent tracker traffic means the banner does not actually block.
export const CMP_SELECTORS = [
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
];

// Entries may be a bare hostname ("hotjar.com") or host+path
// ("googletagmanager.com/gtm.js"); path-qualified entries only match when the
// path prefix also matches, so plain GTM container loads are not called GA.
export function matchTracker(url: string): Tracker | undefined {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return undefined;
    }
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    return TRACKERS.find((t) =>
        t.domains.some((entry) => {
            const slash = entry.indexOf("/");
            const entryHost = slash === -1 ? entry : entry.slice(0, slash);
            const entryPath = slash === -1 ? undefined : entry.slice(slash);
            if (host !== entryHost && !host.endsWith(`.${entryHost}`)) return false;
            return !entryPath || path.startsWith(entryPath);
        })
    );
}

export function isTrackingCookie(name: string): boolean {
    const n = name.toLowerCase();
    return TRACKING_COOKIES.some((c) => n.startsWith(c) || n === c);
}
