import { execSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';

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
    targetPluginDir: string;
    rulesDir: string;
    databasePath: string;
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

    const targetPluginDir = requiredOption(
        'target plugin directory',
        valueForFlag(args, '--target-plugin-dir'),
        positional[0],
        environment.TARGET_PLUGIN_DIR,
    );
    const rulesDir = requiredOption(
        'rules directory',
        valueForFlag(args, '--rules-dir'),
        positional[1],
        environment.RULES_DIR,
    );
    const databasePath = resolve(
        valueForFlag(args, '--database-path') ??
        positional[2] ??
        environment.CODEQL_DB_PATH ??
        '.codeql-regression-db',
    );
    const resultsSarif = resolve(
        valueForFlag(args, '--results-sarif') ??
        positional[3] ??
        environment.RESULTS_SARIF ??
        'results.sarif',
    );

    return { targetPluginDir, rulesDir, databasePath, resultsSarif };
};

const shellQuote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;

export const codeqlCommandsFor = (options: ScanOptions): [string, string] => {
    const createCommand = [
        'codeql database create',
        shellQuote(options.databasePath),
        '--language=javascript',
        '--source-root',
        shellQuote(options.targetPluginDir),
    ].join(' ');
    const analyzeCommand = [
        'codeql database analyze',
        shellQuote(options.databasePath),
        shellQuote(options.rulesDir),
        '--format=sarif-latest',
        `--output=${shellQuote(options.resultsSarif)}`,
    ].join(' ');

    return [createCommand, analyzeCommand];
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

const markdownCell = (value: string): string => value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export const formatFindings = (findings: SarifResult[]): string => {
    const rows = findings.flatMap(finding => {
        const locations = finding.locations ?? [];
        const ruleId = markdownCell(ruleIdFor(finding));

        if (locations.length === 0) {
            return [`| ${ruleId} | unknown file | - |`];
        }

        return locations.map(location => {
            const file = markdownCell(fileNameFor(location.physicalLocation?.artifactLocation?.uri));
            const line = location.physicalLocation?.region?.startLine?.toString() ?? '-';
            return `| ${ruleId} | ${file} | ${line} |`;
        });
    });

    return [
        '## CodeQL regression findings',
        '',
        `Found ${findings.length} finding${findings.length === 1 ? '' : 's'} in a safe plugin.`,
        '',
        '| Rule ID | File | Line |',
        '| --- | --- | ---: |',
        ...rows,
    ].join('\n');
};

export const appendStepSummary = (content: string, summaryPath = process.env.GITHUB_STEP_SUMMARY): void => {
    if (!summaryPath) {
        throw new Error('GITHUB_STEP_SUMMARY is not set; cannot write the regression result to the Actions summary.');
    }

    appendFileSync(summaryPath, `${content.trimEnd()}\n\n`, 'utf8');
};

export const runCodeqlScan = (options: ScanOptions): SarifReport => {
    mkdirSync(dirname(options.databasePath), { recursive: true });
    mkdirSync(dirname(options.resultsSarif), { recursive: true });

    const [createCommand, analyzeCommand] = codeqlCommandsFor(options);
    execSync(createCommand, { stdio: 'inherit' });
    execSync(analyzeCommand, { stdio: 'inherit' });

    return parseSarif(options.resultsSarif);
};

export const main = (): void => {
    try {
        const options = resolveScanOptions();
        const report = runCodeqlScan(options);
        const findings = findingsFrom(report);

        if (findings.length === 0) {
            appendStepSummary('## CodeQL regression scan passed\n\nNo findings were reported for this safe plugin.');
            process.exit(0);
        }

        appendStepSummary(formatFindings(findings));
        process.exit(1);
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`CodeQL regression scan failed: ${message}`);

        try {
            appendStepSummary(`## CodeQL regression scan failed\n\n${markdownCell(message)}`);
        } catch (summaryError) {
            console.error(`Unable to append to GITHUB_STEP_SUMMARY: ${String(summaryError)}`);
        }

        process.exit(1);
    }
};

if (require.main === module) main();
