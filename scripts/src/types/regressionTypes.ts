export const regressionScanArtifactSchemaVersion = 1;

export interface RegressionFinding {
    ruleId: string;
    file: string;
    line: number;
    container: string;
    fingerprint: string;
}

export interface RegressionScanArtifact {
    schemaVersion: typeof regressionScanArtifactSchemaVersion;
    plugin: string;
    pluginId: string;
    repositoryUrl: string;
    requiringReview: RegressionFinding[];
    approvedEarlier: RegressionFinding[];
}
