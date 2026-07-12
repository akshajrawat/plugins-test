import { readFileSync, writeFileSync } from 'node:fs';
import { basename, resolve } from 'node:path';

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

export interface ScanOptions {
    resultsSarif: string;
}

const valueForFlag = (args: string[], flag: string): string | undefined => {
    const flagWithValue = args.find(argument => argument.startsWith(`${flag}=`));

    if (flagWithValue) return flagWithValue.slice(flag.length + 1);

    const flagIndex = args.indexOf(flag);
    return flagIndex >= 0 ? args[flagIndex + 1] : undefined;
};

const positionalArguments = (args: string[]): string[] => {
    const positional: string[] = [];

    for (let index = 0; index < args.length; index++) {
        const argument = args[index];

        if (argument.startsWith('--')) {
            if (!argument.includes('=')) index++;
            continue;
        }

        positional.push(argument);
    }

    return positional;
};

const requiredOption = (
    name: string,
    flagValue: string | undefined,
    positionalValue: string | undefined,
    environmentValue: string | undefined,
): string => {
    const value = flagValue ?? positionalValue ?? environmentValue;

    if (!value) {
        throw new Error(
            `Missing ${name}. Provide it as a command-line argument or set the corresponding environment variable.`,
        );
    }

    return resolve(value);
};

export const resolveScanOptions = (
    args: string[] = process.argv.slice(2),
    environment: NodeJS.ProcessEnv = process.env,
): ScanOptions => {
    const positional = positionalArguments(args);

    const resultsSarif = resolve(
        valueForFlag(args, '--results-sarif') ??
        positional[0] ??
        environment.RESULTS_SARIF ??
        'results.sarif',
    );

    return { resultsSarif };
};



export const parseSarif = (resultsSarif: string): SarifReport => {
    const parsed: unknown = JSON.parse(readFileSync(resultsSarif, 'utf8'));

    if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as SarifReport).runs)) {
        throw new Error(`Invalid SARIF report: ${resultsSarif}`);
    }

    return parsed as SarifReport;
};

export const findingsFrom = (report: SarifReport): SarifResult[] => {
    return (report.runs ?? []).flatMap(run => run.results ?? []);
};

const ruleIdFor = (finding: SarifResult): string => {
    return finding.ruleId ?? finding.rule?.id ?? 'unknown-rule';
};

const fileNameFor = (uri: string | undefined): string => {
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



export const runCodeqlScan = (options: ScanOptions): SarifReport => {
    return parseSarif(options.resultsSarif);
};

export const main = (): void => {
    try {
        const options = resolveScanOptions();
        const report = runCodeqlScan(options);
        const findings = findingsFrom(report);
        const pluginName = process.env.PLUGIN_NAME || 'unknown-plugin';

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

        writeFileSync('findings.json', JSON.stringify(extractedFindings, null, 2));
        process.exit(0);
    } catch (error) {
        console.error(`CodeQL regression scan failed:`, error);
        process.exit(1);
    }
};

if (require.main === module) main();
