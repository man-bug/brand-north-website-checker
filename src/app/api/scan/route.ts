import { NextResponse } from "next/server";
import { scan } from "@/lib/scanner";
import { InvalidUrlError, validateUrl } from "@/lib/validate-url";

export async function POST(request: Request) {
    let input: unknown;
    try {
        ({ input } = (await request.json()) as { input?: unknown });
    } catch {
        return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
    }
    if (typeof input !== "string" || input.trim() === "") {
        return NextResponse.json({ error: "Enter a website URL." }, { status: 400 });
    }

    let url: string;
    try {
        url = await validateUrl(input);
    } catch (error) {
        const message =
            error instanceof InvalidUrlError
                ? error.message
                : "That URL could not be validated.";
        return NextResponse.json({ error: message }, { status: 400 });
    }

    try {
        const report = await scan(url);
        return NextResponse.json(report);
    } catch (error) {
        console.error("scan failed", error);
        return NextResponse.json(
            {
                error: "The site could not be scanned. It may be down or blocking automated visitors.",
            },
            { status: 502 }
        );
    }
}
