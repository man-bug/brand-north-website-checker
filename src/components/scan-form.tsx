"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { HugeiconsIcon } from "@hugeicons/react";
import { AlertCircle } from "@hugeicons/core-free-icons";
import type { Confidence, Grade, ScanReport, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const GRADE_STYLES: Record<Grade, string> = {
    A: "bg-emerald-600/10 text-emerald-700",
    B: "bg-lime-600/10 text-lime-700",
    C: "bg-amber-600/10 text-amber-700",
    D: "bg-orange-600/10 text-orange-700",
    F: "bg-red-600/10 text-red-700",
};

const SEVERITY_STYLES: Record<Severity, string> = {
    High: "bg-red-600/10 text-red-700",
    Medium: "bg-amber-600/10 text-amber-700",
    Low: "bg-sky-600/10 text-sky-700",
};

const CONFIDENCE_LABELS: Record<Confidence, string> = {
    verified: "Direct evidence",
    inferred: "Inferred",
    unverifiable: "Could not verify",
};

const CONFIDENCE_STYLES: Record<Confidence, string> = {
    verified: "text-emerald-700",
    inferred: "text-amber-700",
    unverifiable: "text-muted-foreground",
};

const PDF_ERROR = "PDF export failed. Please try again.";

export function ScanForm() {
    const [url, setUrl] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [report, setReport] = useState<ScanReport | null>(null);
    const [exporting, setExporting] = useState(false);

    async function downloadPdf() {
        if (!report || exporting) return;
        setExporting(true);
        try {
            const response = await fetch("/api/report/pdf", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(report),
                signal: AbortSignal.timeout(90_000),
            });
            if (!response.ok) {
                const body = await response.json().catch(() => null);
                setError(body?.error ?? PDF_ERROR);
                return;
            }
            const blob = await response.blob();
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = `website-checker-${new URL(report.targetUrl).hostname}.pdf`;
            link.click();
            URL.revokeObjectURL(link.href);
        } catch {
            setError(PDF_ERROR);
        } finally {
            setExporting(false);
        }
    }

    async function handleSubmit(event: React.SubmitEvent<HTMLFormElement>) {
        event.preventDefault();
        if (loading) return;
        setLoading(true);
        setError(null);
        setReport(null);
        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ input: url }),
                signal: AbortSignal.timeout(90_000),
            });
            const body = await response.json();
            if (!response.ok) {
                setError(
                    body?.error ?? "Something went wrong. Please try a different URL."
                );
            } else {
                setReport(body as ScanReport);
            }
        } catch {
            setError(
                "The scan timed out. Some sites block automated visitors or load slowly."
            );
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="flex w-full flex-col gap-6">
            <form onSubmit={handleSubmit} className="flex w-full gap-2">
                <Input
                    // type="url" would demand a scheme client-side; the
                    // server normalizes bare domains, so keep validation there.
                    type="text"
                    inputMode="url"
                    placeholder="https://example.com"
                    aria-label="Website URL"
                    className="h-10"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                />
                <Button type="submit" size="lg" className="h-10" disabled={loading}>
                    {loading ? "Scanning…" : "Scan"}
                </Button>
            </form>

            <div className="flex gap-2 items-center justify-center text-muted-foreground">
                <HugeiconsIcon icon={AlertCircle} size={16} />
                <small className="text-xs">
                    Note that only the exact path provided will be scanned.
                </small>
            </div>

            {loading && (
                <p className="animate-pulse text-center text-sm text-muted-foreground">
                    We load the site in a real browser and watch its network traffic. This
                    can take up to a minute.
                </p>
            )}

            {error && (
                <p role="alert" className="text-destructive text-sm">
                    {error}
                </p>
            )}

            {report && (
                <section className="flex flex-col gap-4" aria-label="Scan report">
                    <div className="flex items-center gap-4">
                        <div
                            className={cn(
                                "flex size-14 items-center justify-center rounded-full font-heading text-2xl font-bold",
                                GRADE_STYLES[report.grade]
                            )}
                        >
                            {report.grade}
                        </div>
                        <div>
                            <p className="font-heading font-semibold">
                                {report.riskLevel} risk
                            </p>
                            <p className="text-muted-foreground text-sm">
                                {report.thirdPartyDomains.length} third-party domains
                                observed
                            </p>
                        </div>
                        <Button
                            variant="outline"
                            size="sm"
                            className="ml-auto"
                            onClick={downloadPdf}
                            disabled={exporting}
                        >
                            {exporting ? "Preparing PDF…" : "Download PDF"}
                        </Button>
                    </div>

                    <p className="text-pretty text-sm">{report.summary}</p>

                    {report.findings.length > 0 && (
                        <ul className="flex flex-col gap-3">
                            {report.findings.map((finding) => (
                                <li
                                    key={finding.id}
                                    className="bg-card flex flex-col gap-1.5 rounded-xl border p-4"
                                >
                                    <div className="flex flex-wrap items-center gap-2">
                                        <span
                                            className={cn(
                                                "rounded-full px-2 py-0.5 text-xs font-medium",
                                                SEVERITY_STYLES[finding.severity]
                                            )}
                                        >
                                            {finding.severity}
                                        </span>
                                        <span className="text-muted-foreground text-xs">
                                            {finding.category}
                                        </span>
                                        <span
                                            className={cn(
                                                "ml-auto text-xs font-medium",
                                                CONFIDENCE_STYLES[finding.confidence]
                                            )}
                                            title="How this finding was established"
                                        >
                                            {CONFIDENCE_LABELS[finding.confidence]}
                                        </span>
                                    </div>
                                    <p className="font-heading text-sm font-semibold">
                                        {finding.title}
                                    </p>
                                    <p className="text-muted-foreground text-sm">
                                        <span className="font-medium text-foreground">
                                            Evidence:{" "}
                                        </span>
                                        {finding.evidence}
                                    </p>
                                    <p className="text-muted-foreground text-sm">
                                        <span className="font-medium text-foreground">
                                            Why it matters:{" "}
                                        </span>
                                        {finding.hipaaRisk}
                                    </p>
                                    <p className="text-sm">
                                        <span className="font-medium">Fix: </span>
                                        {finding.recommendation}
                                    </p>
                                </li>
                            ))}
                        </ul>
                    )}

                    {report.thirdPartyDomains.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                            {report.thirdPartyDomains.map((tp) => (
                                <span
                                    key={tp.domain}
                                    className="bg-muted text-muted-foreground rounded-full px-2.5 py-0.5 text-xs"
                                >
                                    {tp.domain} ({tp.requestCount})
                                </span>
                            ))}
                        </div>
                    )}

                    <small className="text-muted-foreground text-center border-t pt-4 text-xs">
                        Not legal advice or a HIPAA compliance certification.
                    </small>
                </section>
            )}
        </div>
    );
}
