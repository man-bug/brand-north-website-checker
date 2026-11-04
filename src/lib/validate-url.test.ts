import { strict } from "node:assert";
import test from "node:test";
import { isBlocked, validateUrl } from "./validate-url.ts";

const cases: [string, boolean][] = [
    ["104.20.23.154", false],
    ["2606:4700:10::ac42:93f3", false],
    ["2001:db8::1", false],
    ["10.1.2.3", true],
    ["127.0.0.1", true],
    ["169.254.169.254", true],
    ["192.168.1.1", true],
    ["100.100.1.1", true],
    ["224.0.0.1", true],
    ["::1", true],
    ["::ffff:10.0.0.1", true],
    ["fd12::1", true],
    ["fe80::1", true],
];

test("blocked ranges", () => {
    for (const [addr, want] of cases) {
        strict.equal(isBlocked(addr), want, addr);
    }
});

test("scheme-less input gets https prepended", async () => {
    // validateUrl resolves DNS, so use a host that stays in the guard's
    // error path after normalization: the thrown message proves parsing
    // and local-check ran on the rewritten value.
    await strict.rejects(
        () => validateUrl("localhost"),
        /Local addresses are not allowed/
    );
    await strict.rejects(
        () => validateUrl("localhost:3000"),
        /Local addresses are not allowed/
    );
    // Explicit schemes pass through untouched.
    await strict.rejects(() => validateUrl("ftp://example.com"), /Only http and https/);
    await strict.rejects(
        () => validateUrl("http://localhost"),
        /Local addresses are not allowed/
    );
});
