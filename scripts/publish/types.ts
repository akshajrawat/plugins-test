import type { SubmissionPayload } from '../code-scan/types';

export interface PublishPayload extends SubmissionPayload {
    repo_name: string;
}

export interface PublishSummary {
    pluginId?: string;
    pluginVersion?: string;
    pluginDirectory?: string;
    registryUpdated?: boolean;
    readmeUpdated?: boolean;
    statsUpdated?: boolean;
    releaseUpdated?: boolean;
}
