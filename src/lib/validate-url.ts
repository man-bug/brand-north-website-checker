import { lookup } from "dns/promises";
import ipaddr from "ipaddr.js";

// User-submitted URLs are untrusted, obviously: the server resolves and fetches
// them, so a hostile value must never be able to reach internal addresses (SSRF),
// including the AWS metadata service.

const BLOCKED_V4: [string, number][] = [
    ["0.0.0.0", 8], // "this network"
    ["10.0.0.0", 8], // private
    ["100.64.0.0", 10], // CGNAT
    ["127.0.0.0", 8], // loopback
    ["169.254.0.0", 16], // link-local, incl. AWS IMDS 169.254.169.254
    ["172.16.0.0", 12], // private
    ["192.0.0.0", 24], // IETF protocol assignments
    ["192.0.2.0", 24], // TEST-NET-1
    ["192.88.99.0", 24], // 6to4 relay
    ["192.168.0.0", 16], // private
    ["198.18.0.0", 15], // benchmarking
    ["198.51.100.0", 24], // TEST-NET-2
    ["203.0.113.0", 24], // TEST-NET-3
    ["224.0.0.0", 3], // multicast + reserved
];

const BLOCKED_V6: [string, number][] = [
    ["::", 128], // unspecified
    ["::1", 128], // loopback
    ["fc00::", 7], // unique-local
    ["fe80::", 10], // link-local
    ["ff00::", 8], // multicast
];

export function isBlocked(addr: string): boolean {
    const parsed = ipaddr.parse(addr);
    let range = parsed;
    if (parsed.kind() === "ipv6") {
        const v6 = parsed as ipaddr.IPv6;
        // Mapped form like ::ffff:10.0.0.1 is really an IPv4 target.
        if (v6.isIPv4MappedAddress()) range = v6.toIPv4Address();
    }
    const table = range.kind() === "ipv4" ? BLOCKED_V4 : BLOCKED_V6;
    return table.some(([base, bits]) => range.match(ipaddr.parse(base), bits));
}

export class InvalidUrlError extends Error {}

export async function validateUrl(rawInput: string): Promise<string> {
    // Users type bare domains; assume HTTPS rather than demanding a scheme.
    const input = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawInput.trim())
        ? rawInput.trim()
        : `https://${rawInput.trim()}`;

    let url: URL;
    try {
        url = new URL(input);
    } catch {
        throw new InvalidUrlError("Not a valid URL.");
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new InvalidUrlError("Only http and https URLs are supported.");
    }
    if (url.username || url.password) {
        throw new InvalidUrlError("URLs with embedded credentials are not allowed.");
    }
    if (url.hostname === "localhost" || url.hostname.endsWith(".localhost")) {
        throw new InvalidUrlError("Local addresses are not allowed.");
    }

    // Resolve before scanning: the value we check is the IP the server would
    // actually connect to. Scanning follows the first A/AAAA record.
    let addresses: { address: string }[];
    try {
        addresses = await lookup(url.hostname, { all: true, verbatim: true });
    } catch {
        throw new InvalidUrlError("Could not resolve that domain.");
    }

    if (addresses.length === 0 || addresses.some((a) => isBlocked(a.address))) {
        throw new InvalidUrlError("That address is not allowed.");
    }

    return url.toString();
}
