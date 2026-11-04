import type { Metadata } from "next";
import { Manrope, DM_Sans } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";

const dmSansHeading = DM_Sans({ subsets: ["latin"], variable: "--font-heading" });

const manrope = Manrope({ subsets: ["latin"], variable: "--font-sans" });

export const metadata: Metadata = {
    title: "Website Checker",
    description:
        "Check any website for HIPAA and PHI privacy risks: trackers, leaky forms, missing security headers.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
    return (
        <html
            lang="en"
            className={cn(
                "h-full",
                "antialiased",
                "font-sans",
                manrope.variable,
                dmSansHeading.variable
            )}
        >
            <body className="min-h-full flex flex-col">{children}</body>
        </html>
    );
}
