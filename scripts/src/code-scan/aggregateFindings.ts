import { readFileSync, appendFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

export interface Finding {
    plugin: string;
    ruleId: string;
    file: string;
    line: string;
}

const appendStepSummary = (content: string, summaryPath = process.env.GITHUB_STEP_SUMMARY): void => {
    if (!summaryPath) {
        throw new Error('GITHUB_STEP_SUMMARY is not set; cannot write the regression result to the Actions summary.');
    }
    appendFileSync(summaryPath, `${content.trimEnd()}\n\n`, 'utf8');
};

const main = (): void => {
    try {
        const artifactsDir = process.env.ARTIFACTS_DIR || resolve('findings');
        const allFindings: Finding[] = [];

        // Search recursively for findings.json files
        const findJsonFiles = (dir: string) => {
            let files: string[] = [];
            for (const item of readdirSync(dir)) {
                const fullPath = join(dir, item);
                if (statSync(fullPath).isDirectory()) {
                    files = files.concat(findJsonFiles(fullPath));
                } else if (item === 'findings.json') {
                    files.push(fullPath);
                }
            }
            return files;
        };

        let jsonFiles: string[] = [];
        try {
            jsonFiles = findJsonFiles(artifactsDir);
        } catch (e) { }

        for (const file of jsonFiles) {
            try {
                const data = JSON.parse(readFileSync(file, 'utf8')) as Finding[];
                allFindings.push(...data);
            } catch (error) {
                console.error(`Error parsing ${file}:`, error);
            }
        }

        if (allFindings.length === 0) {
            appendStepSummary('## CodeQL regression scan passed\n\nNo findings were reported across all tested plugins.');
            process.exit(0);
        }

        const rows = allFindings.map(f => {
            const plugin = f.plugin.replace(/\|/g, '\\|');
            const ruleId = f.ruleId.replace(/\|/g, '\\|');
            const file = f.file.replace(/\|/g, '\\|');
            const line = f.line;
            return `| ${plugin} | ${ruleId} | ${file} | ${line} |`;
        });

        const table = [
            '## CodeQL regression findings',
            '',
            `Found ${allFindings.length} finding${allFindings.length === 1 ? '' : 's'} across the tested safe plugins.`,
            '',
            '| Plugin | Rule ID | File | Line |',
            '| --- | --- | --- | ---: |',
            ...rows,
        ].join('\n');

        appendStepSummary(table);
        process.exit(1);

    } catch (error) {
        console.error('Aggregation failed:', error);
        process.exit(1);
    }
};

if (require.main === module) main();
