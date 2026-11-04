import { NextResponse } from "next/server";
import { launchBrowser } from "@/lib/browser";
import { buildReportHtml } from "@/lib/report-pdf";
import type { ScanReport } from "@/lib/types";

const MAX_BODY_BYTES = 2_000_000;

export async function POST(request: Request) {
    let report: ScanReport;
    try {
        const body = await request.text();
        if (body.length > MAX_BODY_BYTES) {
            return NextResponse.json({ error: "Report too large." }, { status: 413 });
        }
        report = JSON.parse(body) as ScanReport;
    } catch {
        return NextResponse.json({ error: "Invalid report data." }, { status: 400 });
    }
    if (typeof report?.targetUrl !== "string" || !Array.isArray(report?.findings)) {
        return NextResponse.json({ error: "Invalid report data." }, { status: 400 });
    }

    let host = "report";
    try {
        host = new URL(report.targetUrl).hostname;
    } catch {
        // Filename falls back to a generic label.
    }

    try {
        const browser = await launchBrowser();
        try {
            const page = await browser.newPage();
            await page.setContent(buildReportHtml(report), { waitUntil: "load" });
            const pdf = await page.pdf({
                format: "A4",
                printBackground: true,
                margin: { top: "16mm", bottom: "16mm", left: "14mm", right: "14mm" },
            });
            return new NextResponse(pdf as unknown as BodyInit, {
                headers: {
                    "Content-Type": "application/pdf",
                    "Content-Disposition": `attachment; filename="website-checker-${host}.pdf"`,
                },
            });
        } finally {
            await browser.close();
        }
    } catch (error) {
        console.error("pdf generation failed", error);
        return NextResponse.json(
            { error: "The PDF could not be generated. Try again." },
            { status: 502 }
        );
    }
}
