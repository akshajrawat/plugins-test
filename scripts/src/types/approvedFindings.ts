import type { SarifResult } from './types';

export interface FindingIdentity {
    fingerprint: string;
    ruleId: string;
    file: string;
    container: string;
    statementHash: string;
    flowHash: string | null;
    lineHint: number;
    columnHint: number;
}

export interface FingerprintedSarifResult {
    result: SarifResult;
    identity: FindingIdentity;
}

export interface ScanFindingsArtifact {
    schemaVersion: 1;
    pluginId: string;
    repositoryUrl: string;
    commitHash: string;
    issueNumber: number;
    runId: number;
    generatedAt: string;
    findings: FindingIdentity[];
}

export interface ApprovedFindingsBaseline {
    schemaVersion: 1;
    pluginId: string;
    repositoryUrl: string;
    approvedScan: {
        commitHash: string;
        issueNumber: number;
        runId: number;
        approvedBy: string;
        approvedAt: string;
    };
    findings: FindingIdentity[];
}

export interface ExpectedScanArtifact {
    pluginId: string;
    repositoryUrl: string;
    commitHash: string;
    issueNumber: number;
    runId: number;
}
