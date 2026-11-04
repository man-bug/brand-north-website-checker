export type Severity = "High" | "Medium" | "Low";

export type Category =
    | "Unconsented Tracking"
    | "Form & PHI Leakage"
    | "Infrastructure & Policy";

export type Confidence = "verified" | "inferred" | "unverifiable";

export interface Finding {
    id: string;
    severity: Severity;
    confidence: Confidence;
    category: Category;
    title: string;
    evidence: string;
    hipaaRisk: string;
    recommendation: string;
}

export interface ThirdPartyDomain {
    domain: string;
    category: string;
    requestCount: number;
}

export type Grade = "A" | "B" | "C" | "D" | "F";

export interface ScanReport {
    targetUrl: string;
    scannedAt: string;
    grade: Grade;
    riskLevel: "Low" | "Medium" | "High";
    summary: string;
    thirdPartyDomains: ThirdPartyDomain[];
    findings: Finding[];
}
