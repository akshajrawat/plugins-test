import type { GithubApiContext } from '../types/types';
import type { PublishPayload } from '../types/publishTypes';
import { normalizeRepositoryUrl } from '../utils/payload';
import { scanFindingsArtifactName } from '../code-scan/approvedFindings';

export interface CompletedScanReport {
    pluginId: string;
    repositoryUrl: string;
    commitHash: string;
    issueNumber: number;
    runId: number;
    artifactName: string;
    artifactReady: true;
}

const metadataFromReport = (body: string): CompletedScanReport | null => {
    const match = body.match(/<!-- security-scan-metadata:(\{[^\r\n]*\}) -->/);
    if (!match) return null;

    try {
        const parsed: unknown = JSON.parse(match[1]);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
        const metadata = parsed as Record<string, unknown>;

        if (
            metadata.schemaVersion !== 1
            || typeof metadata.pluginId !== 'string'
            || typeof metadata.repositoryUrl !== 'string'
            || typeof metadata.commitHash !== 'string'
            || !Number.isInteger(metadata.issueNumber)
            || !Number.isInteger(metadata.runId)
            || metadata.artifactName !== scanFindingsArtifactName
            || metadata.artifactReady !== true
        ) return null;

        return metadata as unknown as CompletedScanReport;
    } catch {
        return null;
    }
};

export const scanReportMetadataForPayload = (
    body: string,
    payload: PublishPayload,
    issueNumber?: number,
) => {
    if (!body.includes('# Security Scan Report') || !body.includes('# Findings Requiring Review')) return null;
    if (body.includes('# Security Scan Failed')) return null;

    const metadata = metadataFromReport(body);
    if (!metadata) return null;
    if (issueNumber !== undefined && metadata.issueNumber !== issueNumber) return null;

    const normalizedScannedUrl = normalizeRepositoryUrl(metadata.repositoryUrl);
    const normalizedPayloadUrl = normalizeRepositoryUrl(payload.repository_url);
    if (
        normalizedScannedUrl !== normalizedPayloadUrl
        || metadata.commitHash.toLowerCase() !== payload.commit_hash.toLowerCase()
    ) return null;

    return metadata;
};

export const scanReportMatchesPayload = (body: string, payload: PublishPayload) => {
    return scanReportMetadataForPayload(body, payload) !== null;
};

export const completedScanReportFor = async (
    { github, context }: GithubApiContext,
    payload: PublishPayload,
): Promise<CompletedScanReport | null> => {
    const comments = await github.paginate(github.rest.issues.listComments, {
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        per_page: 100,
    });

    const newestFirst = [...comments].sort((a, b) => {
        return Date.parse(b.updated_at ?? b.created_at ?? '') - Date.parse(a.updated_at ?? a.created_at ?? '');
    });

    for (const comment of newestFirst) {
        const metadata = scanReportMetadataForPayload(comment.body ?? '', payload, context.issue.number);
        if (metadata) return metadata;
    }

    return null;
};

export const hasCompletedScanReport = async (context: GithubApiContext, payload: PublishPayload) => {
    return (await completedScanReportFor(context, payload)) !== null;
};
