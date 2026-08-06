import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';

export interface SarifLocation {
    physicalLocation?: {
        artifactLocation?: {
            uri?: string;
        };
        region?: {
            startLine?: number;
        };
    };
}

export interface SarifResult {
    ruleId?: string;
    rule?: {
        id?: string;
    };
    locations?: SarifLocation[];
}

export interface SarifReport {
    runs?: Array<{
        results?: SarifResult[];
    }>;
}

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

export const findingsFrom = (report: SarifReport) => {
    return (report.runs ?? []).flatMap(run => run.results ?? []);
};

const ruleIdFor = (finding: SarifResult) => {
    return finding.ruleId ?? finding.rule?.id ?? 'unknown-rule';
};

const fileNameFor = (uri: string | undefined) => {
    if (!uri) return 'unknown file';

    let normalized = uri;
    try {
        normalized = decodeURIComponent(normalized);
    } catch {
        // Keep the original URI when it contains malformed escape sequences.
    }

    normalized = normalized
        .replace(/^file:\/\//, '')
        .replace(/\\/g, '/')
        .replace(/^\/+/, '');

    const targetPluginMarker = 'target-plugin/';
    const targetPluginIndex = normalized.lastIndexOf(targetPluginMarker);
    if (targetPluginIndex >= 0) return normalized.slice(targetPluginIndex + targetPluginMarker.length);

    return normalized || basename(uri);
};

export const main = async () => {
    try {
        const resultsSarif = requiredEnvironmentValue('RESULTS_SARIF');
        const pluginName = requiredEnvironmentValue('PLUGIN_NAME');
        const report = await parseSarif(resultsSarif);
        const findings = findingsFrom(report);

        const extractedFindings = findings.flatMap(finding => {
            const locations = finding.locations ?? [];
            const ruleId = ruleIdFor(finding);

            if (locations.length === 0) {
                return [{ plugin: pluginName, ruleId, file: 'unknown file', line: '-' }];
            }

            return locations.map(location => {
                const file = fileNameFor(location.physicalLocation?.artifactLocation?.uri);
                const line = location.physicalLocation?.region?.startLine?.toString() ?? '-';
                return { plugin: pluginName, ruleId, file, line };
            });
        });

        await writeFile('findings.json', JSON.stringify(extractedFindings, null, 2));
        process.exit(0);
    } catch (error) {
        console.error(`CodeQL regression scan failed:`, error);
        process.exit(1);
    }
};

if (require.main === module) void main();
