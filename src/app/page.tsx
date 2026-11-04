import { ScanForm } from "@/components/scan-form";
import { Manbug } from "@/components/manbug";

export default function Home() {
    return (
        <main className="flex min-h-svh flex-1 flex-col items-center px-4 py-4 md:py-8 lg:py-12">
            <div className="flex w-full max-w-md flex-col items-center gap-6">
                <Manbug className="size-20" />
                <div className="flex flex-col items-center gap-2 text-center">
                    <h1 className="font-heading text-4xl font-semibold tracking-tight">
                        Website Checker
                    </h1>
                    <p className="text-balance text-muted-foreground">
                        Check any website for HIPAA and PHI privacy risks: trackers, leaky
                        forms, missing security headers.
                    </p>
                </div>
                <ScanForm />
            </div>
        </main>
    );
}
