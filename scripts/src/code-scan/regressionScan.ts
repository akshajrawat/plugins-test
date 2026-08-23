import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { FingerprintedSarifResult } from '../types/approvedFindings';
import {
    regressionScanArtifactSchemaVersion,
    type RegressionFinding,
    type RegressionScanArtifact,
} from '../types/regressionTypes';
import type { SarifReport } from '../types/types';
import { normalizeRepositoryUrl } from '../utils/payload';
import { classifyFindings, fingerprintSarifResults, readApprovedBaseline } from './approvedFindings';

const requiredEnvironmentValue = (name: string) => {
    const value = process.env[name];

    if (!value) {
        throw new Error(`${name} is required.`);
    }

    return value;
};

export const parseSarif = async (resultsSarif: string) => {
    const parsed: unknown = JSON.parse(await readFile(resultsSarif, 'utf8'));

    if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as SarifReport).runs)) {
        throw new Error(`Invalid SARIF report: ${resultsSarif}`);
    }

    return parsed as SarifReport;
};

const regressionFindingFrom = (finding: FingerprintedSarifResult): RegressionFinding => ({
    ruleId: finding.identity.ruleId,
    file: finding.identity.file,
    line: finding.identity.lineHint,
    container: finding.identity.container,
    fingerprint: finding.identity.fingerprint,
});

export const main = async () => {
    try {
        const resultsSarif = requiredEnvironmentValue('RESULTS_SARIF');
        const pluginName = requiredEnvironmentValue('PLUGIN_NAME');
        const pluginRepositoryUrl = requiredEnvironmentValue('PLUGIN_REPOSITORY_URL');
        const sourceRoot = requiredEnvironmentValue('SOURCE_ROOT');
        const registryRoot = requiredEnvironmentValue('REGISTRY_ROOT');
        const report = await parseSarif(resultsSarif);
        const manifestPath = resolve(sourceRoot, 'src', 'manifest.json');
        const manifest: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
        if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
            throw new Error(`Invalid plugin manifest: ${manifestPath}`);
        }

        const pluginId = (manifest as Record<string, unknown>).id;
        if (typeof pluginId !== 'string' || !pluginId) throw new Error(`Plugin manifest is missing id: ${manifestPath}`);

        const fingerprinted = await fingerprintSarifResults(report, sourceRoot);
        const baseline = await readApprovedBaseline(registryRoot, pluginId, pluginRepositoryUrl);
        const { requiringReview, approvedEarlier } = classifyFindings(fingerprinted, baseline);
        const artifact: RegressionScanArtifact = {
            schemaVersion: regressionScanArtifactSchemaVersion,
            plugin: pluginName,
            pluginId,
            repositoryUrl: normalizeRepositoryUrl(pluginRepositoryUrl),
            requiringReview: requiringReview.map(regressionFindingFrom),
            approvedEarlier: approvedEarlier.map(regressionFindingFrom),
        };

        await writeFile('findings.json', `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
        process.exit(0);
    } catch (error) {
        console.error(`CodeQL regression scan failed:`, error);
        process.exit(1);
    }
};

if (require.main === module) void main();
