import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import type { SarifReport, SarifResult } from '../types/types';
import type { PublishPayload } from '../types/publishTypes';
import {
    baselinePathFor,
    classifyFindings,
    createScanArtifact,
    fingerprintSarifResults,
    readApprovedBaseline,
    replaceApprovedBaseline,
    validateScanArtifact,
} from '../code-scan/approvedFindings';
import { renderFinalReport } from '../code-scan/scanReport';
import { scanReportMetadataForPayload } from '../publish/scanUtils';
import { rejectWithIssueComment } from '../utils/github';

const pluginId = 'org.example.backup';
const repositoryUrl = 'https://github.com/example/backup-plugin';
const commitHash = 'a'.repeat(40);

const resultAt = (
    file: string,
    line: number,
    column: number,
    ruleId = 'js/joplin/command-execution-structural',
    codeFlows?: SarifResult['codeFlows'],
): SarifResult => ({
    ruleId,
    message: { text: 'Review this command.' },
    locations: [{
        physicalLocation: {
            artifactLocation: { uri: `target-plugin/${file}` },
            region: { startLine: line, startColumn: column },
        },
    }],
    codeFlows,
});

const reportWith = (...results: SarifResult[]): SarifReport => ({
    runs: [{
        tool: {
            driver: {
                rules: [{
                    id: 'js/joplin/command-execution-structural',
                    name: 'Command execution',
                    defaultConfiguration: { level: 'warning' },
                }],
            },
        },
        results,
    }],
});

const writeSource = async (root: string, file: string, source: string) => {
    const path = join(root, file);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, source, 'utf8');
};

const withTemporaryRepository = async (callback: (root: string, sourceRoot: string) => Promise<void>) => {
    const root = await mkdtemp(join(tmpdir(), 'approved-findings-test-'));
    const sourceRoot = join(root, 'target-plugin');
    await mkdir(sourceRoot, { recursive: true });
    try {
        await callback(root, sourceRoot);
    } finally {
        await rm(root, { recursive: true, force: true });
    }
};

test('whole-statement fingerprints survive line movement and reject material changes', async () => {
    await withTemporaryRepository(async (_root, sourceRoot) => {
        const original = [
            'function backup() {',
            '    childProcess.execFile(',
            "        'cp',",
            "        ['source', 'destination'],",
            '    );',
            '}',
            '',
        ].join('\n');
        await writeSource(sourceRoot, 'src/index.ts', original);
        const first = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 3, 9)), sourceRoot);

        await writeSource(sourceRoot, 'src/index.ts', `// moved down\n\n${original}`);
        const moved = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 5, 9)), sourceRoot);
        assert.equal(moved[0].identity.fingerprint, first[0].identity.fingerprint);
        assert.notEqual(moved[0].identity.lineHint, first[0].identity.lineHint);

        await writeSource(sourceRoot, 'src/index.ts', original.replace("'destination'", "'other-destination'"));
        const changedArgument = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 3, 9)), sourceRoot);
        assert.notEqual(changedArgument[0].identity.fingerprint, first[0].identity.fingerprint);

        await writeSource(sourceRoot, 'src/index.ts', original.replace('function backup()', 'function restore()'));
        const changedContainer = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 3, 9)), sourceRoot);
        assert.notEqual(changedContainer[0].identity.fingerprint, first[0].identity.fingerprint);

        const changedRule = await fingerprintSarifResults(
            reportWith(resultAt('src/index.ts', 3, 9, 'js/joplin/other-rule')),
            sourceRoot,
        );
        assert.notEqual(changedRule[0].identity.fingerprint, first[0].identity.fingerprint);
    });
});

test('path findings include ordered in-repository flow statements', async () => {
    await withTemporaryRepository(async (_root, sourceRoot) => {
        const source = [
            'function run(value: string) {',
            '    const command = value;',
            '    childProcess.exec(command);',
            '}',
            '',
        ].join('\n');
        await writeSource(sourceRoot, 'src/index.ts', source);
        const flow = [{ threadFlows: [{ locations: [
            { location: resultAt('src/index.ts', 2, 11).locations?.[0] },
            { location: resultAt('src/index.ts', 3, 5).locations?.[0] },
        ] }] }];
        const before = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 3, 5, 'js/joplin/command-execution', flow)), sourceRoot);

        await writeSource(sourceRoot, 'src/index.ts', source.replace('const command = value;', 'const command = value.trim();'));
        const after = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 3, 5, 'js/joplin/command-execution', flow)), sourceRoot);

        assert.notEqual(before[0].identity.flowHash, null);
        assert.notEqual(after[0].identity.flowHash, before[0].identity.flowHash);
        assert.notEqual(after[0].identity.fingerprint, before[0].identity.fingerprint);
    });
});

test('whole-statement fingerprints include same-file command and argument declarations', async () => {
    await withTemporaryRepository(async (_root, sourceRoot) => {
        const original = [
            "const command = 'cp';",
            "const args = ['source', 'destination'];",
            'function backup() {',
            '    childProcess.execFile(command, args);',
            '}',
            '',
        ].join('\n');
        await writeSource(sourceRoot, 'src/index.ts', original);
        const first = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 4, 27)), sourceRoot);

        await writeSource(sourceRoot, 'src/index.ts', original.replace("command = 'cp'", "command = 'rm'"));
        const commandChanged = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 4, 27)), sourceRoot);
        assert.notEqual(commandChanged[0].identity.fingerprint, first[0].identity.fingerprint);

        await writeSource(sourceRoot, 'src/index.ts', original.replace("'destination'", "'other-destination'"));
        const argsChanged = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 4, 27)), sourceRoot);
        assert.notEqual(argsChanged[0].identity.fingerprint, first[0].identity.fingerprint);
    });
});

test('classification is plugin-scoped and duplicate fingerprints fail closed', async () => {
    await withTemporaryRepository(async (root, sourceRoot) => {
        await writeSource(sourceRoot, 'src/index.ts', "childProcess.execFile('cp', ['a', 'b']);\n");
        const current = await fingerprintSarifResults(reportWith(resultAt('src/index.ts', 1, 23)), sourceRoot);
        const artifact = createScanArtifact(pluginId, repositoryUrl, commitHash, 10, 20, current);
        const expected = { pluginId, repositoryUrl, commitHash, issueNumber: 10, runId: 20 };
        await replaceApprovedBaseline(root, artifact, expected, 'reviewer', '2026-08-20T00:00:00.000Z');

        const baseline = await readApprovedBaseline(root, pluginId, repositoryUrl);
        assert.equal(classifyFindings(current, baseline).approvedEarlier.length, 1);

        const duplicates = classifyFindings([current[0], current[0]], baseline);
        assert.equal(duplicates.approvedEarlier.length, 0);
        assert.equal(duplicates.requiringReview.length, 2);

        const duplicateArtifact = createScanArtifact(pluginId, repositoryUrl, commitHash, 10, 20, [current[0], current[0]]);
        assert.throws(() => validateScanArtifact(duplicateArtifact, expected), /ambiguous duplicate finding/);

        assert.equal(await readApprovedBaseline(root, 'org.example.other', repositoryUrl), null);
    });
});

test('approval replaces rather than accumulates and an empty scan removes the baseline', async () => {
    await withTemporaryRepository(async (root, sourceRoot) => {
        await writeSource(sourceRoot, 'src/index.ts', [
            "childProcess.execFile('cp', ['a', 'b']);",
            "childProcess.execFile('mv', ['a', 'b']);",
            '',
        ].join('\n'));
        const two = await fingerprintSarifResults(
            reportWith(resultAt('src/index.ts', 1, 23), resultAt('src/index.ts', 2, 23)),
            sourceRoot,
        );
        const expectedOne = { pluginId, repositoryUrl, commitHash, issueNumber: 10, runId: 20 };
        await replaceApprovedBaseline(
            root,
            createScanArtifact(pluginId, repositoryUrl, commitHash, 10, 20, two),
            expectedOne,
            'reviewer',
            '2026-08-20T00:00:00.000Z',
        );

        const expectedTwo = { pluginId, repositoryUrl, commitHash, issueNumber: 11, runId: 21 };
        await replaceApprovedBaseline(
            root,
            createScanArtifact(pluginId, repositoryUrl, commitHash, 11, 21, [two[1]]),
            expectedTwo,
            'reviewer',
            '2026-08-20T01:00:00.000Z',
        );
        const replaced = await readApprovedBaseline(root, pluginId, repositoryUrl);
        assert.deepEqual(replaced?.findings.map(finding => finding.fingerprint), [two[1].identity.fingerprint]);

        const expectedEmpty = { pluginId, repositoryUrl, commitHash, issueNumber: 12, runId: 22 };
        await replaceApprovedBaseline(
            root,
            createScanArtifact(pluginId, repositoryUrl, commitHash, 12, 22, []),
            expectedEmpty,
            'reviewer',
            '2026-08-20T02:00:00.000Z',
        );
        await assert.rejects(readFile(baselinePathFor(root, pluginId), 'utf8'), /ENOENT/);
    });
});

test('malformed baselines and unsafe source paths fail closed', async () => {
    await withTemporaryRepository(async (root, sourceRoot) => {
        const baselinePath = baselinePathFor(root, pluginId);
        await mkdir(dirname(baselinePath), { recursive: true });
        await writeFile(baselinePath, '{"schemaVersion":1}', 'utf8');
        await assert.rejects(readApprovedBaseline(root, pluginId, repositoryUrl), /malformed/);

        await writeSource(sourceRoot, 'src/index.ts', "childProcess.exec('value');\n");
        const unsafe = reportWith(resultAt('../outside.ts', 1, 1));
        await assert.rejects(fingerprintSarifResults(unsafe, sourceRoot), /safe repository-relative path|target repository/);
    });
});

test('final report separates current review from earlier approvals and exposes exact scan metadata', async () => {
    await withTemporaryRepository(async (root, sourceRoot) => {
        await writeSource(sourceRoot, 'src/index.ts', "childProcess.execFile('cp', ['a', 'b']);\n");
        const sarif = reportWith(resultAt('src/index.ts', 1, 23));
        const fingerprinted = await fingerprintSarifResults(sarif, sourceRoot);
        const approved = createScanArtifact(pluginId, repositoryUrl, commitHash, 10, 20, fingerprinted);
        await replaceApprovedBaseline(
            root,
            approved,
            { pluginId, repositoryUrl, commitHash, issueNumber: 10, runId: 20 },
            'reviewer',
            '2026-08-20T00:00:00.000Z',
        );

        const sarifPath = join(root, 'result.sarif');
        const artifactPath = join(root, 'artifact', 'security-scan-findings.json');
        await writeFile(sarifPath, JSON.stringify(sarif), 'utf8');
        const report = await renderFinalReport({
            sarifPath,
            sourceRoot,
            baselineRoot: root,
            artifactPath,
            artifactName: 'security-scan-findings',
            pluginId,
            repoUrl: repositoryUrl,
            commitHash,
            runUrl: 'https://github.com/joplin/plugins-test/actions/runs/21',
            issueNumber: 10,
            runId: 21,
            analysisOutcome: 'success',
            isUpdate: true,
        });

        assert.equal(report.ok, true);
        assert.match(report.body, /# Findings Requiring Review\n\n✅ No findings require a new review/);
        assert.match(report.body, /# Approved Earlier[\s\S]*Command execution/);

        const payload: PublishPayload = {
            plugin_name: 'backup-plugin',
            version: '1.0.0',
            repository_url: repositoryUrl,
            commit_hash: commitHash,
            repo_name: 'example/backup-plugin',
        };
        assert.equal(scanReportMetadataForPayload(report.body, payload, 10), null);
        const readyReportBody = report.body.replace('"artifactReady":false', '"artifactReady":true');
        const metadata = scanReportMetadataForPayload(readyReportBody, payload, 10);
        assert.equal(metadata?.pluginId, pluginId);
        assert.equal(metadata?.runId, 21);
        assert.equal(scanReportMetadataForPayload(readyReportBody, { ...payload, commit_hash: 'b'.repeat(40) }, 10), null);
        assert.equal(scanReportMetadataForPayload(readyReportBody, payload, 11), null);
    });
});

test('submission rejection reports the reason and closes the issue as not planned', async () => {
    const updatedComments: Record<string, unknown>[] = [];
    const updatedIssues: Record<string, unknown>[] = [];
    const outputs: Record<string, string> = {};
    let failureMessage = '';
    const github = {
        rest: {
            issues: {
                updateComment: async (input: Record<string, unknown>) => {
                    updatedComments.push(input);
                },
                update: async (input: Record<string, unknown>) => {
                    updatedIssues.push(input);
                },
            },
        },
    };
    const context = {
        repo: { owner: 'joplin', repo: 'plugins-test' },
        issue: { number: 74 },
        runId: 123,
        serverUrl: 'https://github.com',
    };
    const core = {
        setOutput: (name: string, value: string) => {
            outputs[name] = value;
        },
        setFailed: (message: string) => {
            failureMessage = message;
        },
    };

    const result = await rejectWithIssueComment(
        { github, context, core },
        456,
        'The submitted version is not greater than the published version.',
    );

    assert.deepEqual(result, { should_proceed: false });
    assert.equal(outputs.handled_failure, 'true');
    assert.equal(failureMessage, 'The submitted version is not greater than the published version.');
    assert.match(String(updatedComments[0].body), /# Security Scan Rejected/);
    assert.deepEqual(updatedIssues, [{
        owner: 'joplin',
        repo: 'plugins-test',
        issue_number: 74,
        state: 'closed',
        state_reason: 'not_planned',
    }]);
});
