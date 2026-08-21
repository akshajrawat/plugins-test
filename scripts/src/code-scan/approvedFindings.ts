import { createHash } from 'node:crypto';
import { access, lstat, mkdir, readFile, realpath, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';
import ts from 'typescript';
import type { SarifLocation, SarifReport, SarifResult } from '../types/types';
import { normalizeRepositoryUrl } from '../utils/payload';

export const approvedFindingsSchemaVersion = 1;
export const approvedFindingsDirectory = '.github/codeql/approved-findings';
export const scanFindingsArtifactName = 'security-scan-findings';

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

interface ParsedSource {
    sourceFile: ts.SourceFile;
    checker: ts.TypeChecker;
    realPath: string;
    relativePath: string;
}

const pluginIdPattern = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,254}[A-Za-z0-9])?$/;

const sha256 = (value: string) => {
    return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
};

const canonicalIdentityValue = (identity: Omit<FindingIdentity, 'fingerprint' | 'lineHint' | 'columnHint'>) => {
    return JSON.stringify({
        ruleId: identity.ruleId,
        file: identity.file,
        container: identity.container,
        statementHash: identity.statementHash,
        flowHash: identity.flowHash,
    });
};

const fingerprintFor = (identity: Omit<FindingIdentity, 'fingerprint' | 'lineHint' | 'columnHint'>) => {
    return sha256(canonicalIdentityValue(identity));
};

export const assertValidPluginId: (pluginId: unknown) => asserts pluginId is string = (pluginId) => {
    if (typeof pluginId !== 'string' || !pluginIdPattern.test(pluginId)) {
        throw new Error(`Invalid plugin ID for an approved-findings file: ${String(pluginId)}`);
    }
};

export const baselinePathFor = (registryRoot: string, pluginId: string) => {
    assertValidPluginId(pluginId);
    return resolve(registryRoot, approvedFindingsDirectory, `${pluginId}.json`);
};

const exists = async (path: string) => {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
};

const inside = (parent: string, child: string) => {
    const relativePath = relative(parent, child);
    return relativePath === '' || (!relativePath.startsWith('..') && !isAbsolute(relativePath));
};

const decodeUri = (uri: string) => {
    try {
        return decodeURIComponent(uri);
    } catch {
        throw new Error(`Finding location contains an invalid URI: ${uri}`);
    }
};

const normalizedRelativePath = (uri: string, sourceRoot: string) => {
    let decoded = decodeUri(uri).replace(/^file:\/\//i, '').replace(/\\/g, '/');
    const marker = '/target-plugin/';
    const markerIndex = decoded.lastIndexOf(marker);

    if (markerIndex >= 0) {
        decoded = decoded.slice(markerIndex + marker.length);
    } else if (decoded.startsWith('target-plugin/')) {
        decoded = decoded.slice('target-plugin/'.length);
    } else if (isAbsolute(decoded)) {
        decoded = relative(sourceRoot, decoded).replace(/\\/g, '/');
    }

    decoded = decoded.replace(/^\.\//, '').replace(/^\/+/, '');
    const parts = decoded.split('/');
    if (!decoded || parts.some(part => !part || part === '.' || part === '..')) {
        throw new Error(`Finding location is not a safe repository-relative path: ${uri}`);
    }

    return parts.join('/');
};

const scriptKindFor = (file: string) => {
    switch (extname(file).toLowerCase()) {
        case '.js':
        case '.mjs':
        case '.cjs':
            return ts.ScriptKind.JS;
        case '.jsx':
            return ts.ScriptKind.JSX;
        case '.tsx':
            return ts.ScriptKind.TSX;
        case '.json':
            return ts.ScriptKind.JSON;
        default:
            return ts.ScriptKind.TS;
    }
};

const sourcePosition = (sourceFile: ts.SourceFile, location: SarifLocation) => {
    const region = location.physicalLocation?.region;
    const line = region?.startLine;
    if (!line || line < 1 || line > sourceFile.getLineAndCharacterOfPosition(sourceFile.end).line + 1) {
        throw new Error(`Finding has an invalid start line in ${sourceFile.fileName}.`);
    }

    const lineStart = sourceFile.getPositionOfLineAndCharacter(line - 1, 0);
    const lineEnd = line < sourceFile.getLineAndCharacterOfPosition(sourceFile.end).line + 1
        ? sourceFile.getPositionOfLineAndCharacter(line, 0)
        : sourceFile.end;
    let column = region?.startColumn;

    if (!column) {
        const lineText = sourceFile.text.slice(lineStart, lineEnd);
        column = (lineText.search(/\S/) < 0 ? 0 : lineText.search(/\S/)) + 1;
    }

    const position = lineStart + column - 1;
    if (position < lineStart || position > lineEnd || position > sourceFile.end) {
        throw new Error(`Finding has an invalid start column in ${sourceFile.fileName}.`);
    }

    return position;
};

const deepestNodeAt = (sourceFile: ts.SourceFile, position: number) => {
    let deepest: ts.Node = sourceFile;

    const visit = (node: ts.Node) => {
        if (position < node.getStart(sourceFile, false) || position >= node.getEnd()) return;
        deepest = node;
        node.forEachChild(visit);
    };

    sourceFile.forEachChild(visit);
    return deepest;
};

const isApprovalUnit = (node: ts.Node) => {
    if (ts.isBlock(node) || ts.isEmptyStatement(node)) return false;
    if (ts.isStatement(node)) return true;

    return ts.isPropertyDeclaration(node)
        || ts.isMethodDeclaration(node)
        || ts.isGetAccessorDeclaration(node)
        || ts.isSetAccessorDeclaration(node)
        || ts.isConstructorDeclaration(node)
        || ts.isPropertyAssignment(node)
        || ts.isShorthandPropertyAssignment(node);
};

const approvalUnitFor = (sourceFile: ts.SourceFile, position: number) => {
    let node: ts.Node | undefined = deepestNodeAt(sourceFile, position);

    while (node && !ts.isSourceFile(node)) {
        if (isApprovalUnit(node)) return node;
        node = node.parent;
    }

    throw new Error(`Could not locate a complete enclosing statement in ${sourceFile.fileName}.`);
};

const declarationName = (node: ts.Node): string | null => {
    const named = node as ts.Node & { name?: ts.Node };
    if (named.name) return named.name.getText().replace(/^['"]|['"]$/g, '');

    if (ts.isConstructorDeclaration(node)) return 'constructor';

    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
        const parent = node.parent;
        if (ts.isVariableDeclaration(parent)) return parent.name.getText();
        if (ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)) return parent.name.getText();
    }

    return null;
};

const containerFor = (unit: ts.Node) => {
    const names: string[] = [];
    let node: ts.Node | undefined = unit.parent;

    while (node && !ts.isSourceFile(node)) {
        if (
            ts.isFunctionDeclaration(node)
            || ts.isFunctionExpression(node)
            || ts.isArrowFunction(node)
            || ts.isMethodDeclaration(node)
            || ts.isGetAccessorDeclaration(node)
            || ts.isSetAccessorDeclaration(node)
            || ts.isConstructorDeclaration(node)
            || ts.isClassDeclaration(node)
            || ts.isClassExpression(node)
            || ts.isModuleDeclaration(node)
        ) {
            const name = declarationName(node);
            if (name) names.unshift(name);
        }
        node = node.parent;
    }

    return names.length > 0 ? names.join('.') : '<module>';
};

const canonicalUnitText = (unit: ts.Node, sourceFile: ts.SourceFile) => {
    const printer = ts.createPrinter({ removeComments: true, newLine: ts.NewLineKind.LineFeed });
    return printer.printNode(ts.EmitHint.Unspecified, unit, sourceFile).trim();
};

const dependencyTextsFor = (source: ParsedSource, primaryUnit: ts.Node) => {
    const dependencyUnits = new Map<string, ts.Node>();
    const queuedIdentifiers: ts.Identifier[] = [];
    const visitedIdentifiers = new Set<string>();

    const queueIdentifiers = (node: ts.Node) => {
        const visit = (candidate: ts.Node) => {
            if (ts.isIdentifier(candidate)) queuedIdentifiers.push(candidate);
            candidate.forEachChild(visit);
        };
        node.forEachChild(visit);
    };
    queueIdentifiers(primaryUnit);

    while (queuedIdentifiers.length > 0) {
        const identifier = queuedIdentifiers.shift()!;
        const identifierKey = `${identifier.pos}:${identifier.end}`;
        if (visitedIdentifiers.has(identifierKey)) continue;
        visitedIdentifiers.add(identifierKey);

        const symbol = source.checker.getSymbolAtLocation(identifier);
        for (const declaration of symbol?.declarations ?? []) {
            if (declaration.getSourceFile() !== source.sourceFile) continue;

            let dependencyUnit: ts.Node;
            try {
                dependencyUnit = approvalUnitFor(source.sourceFile, declaration.getStart(source.sourceFile, false));
            } catch {
                continue;
            }

            if (dependencyUnit === primaryUnit) continue;
            const dependencyKey = `${dependencyUnit.pos}:${dependencyUnit.end}`;
            if (dependencyUnits.has(dependencyKey)) continue;
            dependencyUnits.set(dependencyKey, dependencyUnit);

            const containsPrimary = dependencyUnit.getStart(source.sourceFile, false) <= primaryUnit.getStart(source.sourceFile, false)
                && dependencyUnit.getEnd() >= primaryUnit.getEnd();
            if (!containsPrimary) queueIdentifiers(dependencyUnit);
        }
    }

    return [...dependencyUnits.values()]
        .sort((a, b) => a.getStart(source.sourceFile, false) - b.getStart(source.sourceFile, false))
        .map(unit => canonicalUnitText(unit, source.sourceFile));
};

class SourceResolver {
    private readonly cache = new Map<string, ParsedSource>();
    private realRootPromise: Promise<string> | null = null;

    public constructor(private readonly sourceRoot: string) {}

    private realRoot() {
        this.realRootPromise ??= realpath(this.sourceRoot);
        return this.realRootPromise;
    }

    public uriLooksInRepository(uri: string) {
        const decoded = decodeUri(uri).replace(/^file:\/\//i, '').replace(/\\/g, '/');
        return decoded.includes('/target-plugin/')
            || decoded.startsWith('target-plugin/')
            || (!isAbsolute(decoded.replace(/^file:\/\//i, '')) && !decoded.startsWith('node_modules/'));
    }

    public async sourceFor(uri: string): Promise<ParsedSource> {
        const relativePath = normalizedRelativePath(uri, this.sourceRoot);
        const cached = this.cache.get(relativePath);
        if (cached) return cached;

        const root = await this.realRoot();
        const candidate = resolve(root, ...relativePath.split('/'));
        if (!inside(root, candidate)) {
            throw new Error(`Finding path escapes the target repository: ${uri}`);
        }

        const realPath = await realpath(candidate).catch(() => '');
        if (!realPath || !inside(root, realPath)) {
            throw new Error(`Finding path does not resolve to a file inside the target repository: ${uri}`);
        }

        const fileStat = await stat(realPath);
        const linkStat = await lstat(candidate);
        if (!fileStat.isFile() || (linkStat.isSymbolicLink() && !inside(root, realPath))) {
            throw new Error(`Finding path is not a regular source file: ${uri}`);
        }

        const text = await readFile(realPath, 'utf8');
        const sourceFile = ts.createSourceFile(
            realPath,
            text,
            ts.ScriptTarget.Latest,
            true,
            scriptKindFor(relativePath),
        );
        const parseDiagnostics = (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
        if (parseDiagnostics.length > 0) {
            throw new Error(`TypeScript could not parse finding source ${relativePath}.`);
        }

        const compilerOptions: ts.CompilerOptions = {
            allowJs: true,
            checkJs: false,
            jsx: ts.JsxEmit.Preserve,
            noLib: true,
            noResolve: true,
            target: ts.ScriptTarget.Latest,
        };
        const host = ts.createCompilerHost(compilerOptions, true);
        host.fileExists = fileName => resolve(fileName) === resolve(realPath);
        host.readFile = fileName => resolve(fileName) === resolve(realPath) ? text : undefined;
        host.getSourceFile = fileName => resolve(fileName) === resolve(realPath) ? sourceFile : undefined;
        const program = ts.createProgram([realPath], compilerOptions, host);
        const checker = program.getTypeChecker();

        const parsed = { sourceFile, checker, realPath, relativePath };
        this.cache.set(relativePath, parsed);
        return parsed;
    }
}

const statementIdentityAt = async (resolver: SourceResolver, location: SarifLocation) => {
    const uri = location.physicalLocation?.artifactLocation?.uri;
    if (!uri) throw new Error('Finding is missing its source file URI.');

    const source = await resolver.sourceFor(uri);
    const position = sourcePosition(source.sourceFile, location);
    const unit = approvalUnitFor(source.sourceFile, position);
    const statement = canonicalUnitText(unit, source.sourceFile);
    if (!statement) throw new Error(`Finding has an empty enclosing statement in ${source.relativePath}.`);
    const dependencies = dependencyTextsFor(source, unit);

    return {
        file: source.relativePath,
        container: containerFor(unit),
        statementHash: sha256(JSON.stringify({ statement, dependencies })),
    };
};

const flowHashFor = async (resolver: SourceResolver, result: SarifResult) => {
    if (!result.codeFlows || result.codeFlows.length === 0) return null;

    const flows: Array<Array<{ file: string; container: string; statementHash: string }>> = [];

    for (const codeFlow of result.codeFlows) {
        for (const threadFlow of codeFlow.threadFlows ?? []) {
            const anchors: Array<{ file: string; container: string; statementHash: string }> = [];

            for (const threadLocation of threadFlow.locations ?? []) {
                const location = threadLocation.location;
                const uri = location?.physicalLocation?.artifactLocation?.uri;
                if (!location || !uri) continue;

                try {
                    anchors.push(await statementIdentityAt(resolver, location));
                } catch (error) {
                    if (resolver.uriLooksInRepository(uri)) throw error;
                }
            }

            if (anchors.length > 0) flows.push(anchors);
        }
    }

    if (flows.length === 0) {
        throw new Error('A path finding did not contain any verifiable in-repository flow locations.');
    }

    return sha256(JSON.stringify(flows));
};

const ruleIdFor = (result: SarifResult) => {
    const ruleId = result.ruleId ?? result.rule?.id;
    if (!ruleId) throw new Error('SARIF result is missing its rule ID.');
    return ruleId;
};

export const fingerprintSarifResults = async (sarif: SarifReport, sourceRoot: string) => {
    const resolver = new SourceResolver(sourceRoot);
    const results = sarif.runs.flatMap(run => run.results ?? []);
    const fingerprinted: FingerprintedSarifResult[] = [];

    for (const result of results) {
        const location = result.locations?.[0];
        if (!location) throw new Error(`SARIF result ${ruleIdFor(result)} is missing its primary location.`);

        const statement = await statementIdentityAt(resolver, location);
        const flowHash = await flowHashFor(resolver, result);
        const identityWithoutHints = {
            ruleId: ruleIdFor(result),
            file: statement.file,
            container: statement.container,
            statementHash: statement.statementHash,
            flowHash,
        };
        const identity: FindingIdentity = {
            fingerprint: fingerprintFor(identityWithoutHints),
            ...identityWithoutHints,
            lineHint: location.physicalLocation?.region?.startLine ?? 1,
            columnHint: location.physicalLocation?.region?.startColumn ?? 1,
        };

        fingerprinted.push({ result, identity });
    }

    return fingerprinted;
};

const isFindingIdentity = (value: unknown): value is FindingIdentity => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const finding = value as Record<string, unknown>;
    const validHash = (candidate: unknown) => typeof candidate === 'string' && /^sha256:[a-f0-9]{64}$/.test(candidate);
    const file = typeof finding.file === 'string' ? finding.file : '';
    const safeFile = file.length > 0
        && !file.includes('\\')
        && !file.startsWith('/')
        && file.split('/').every(part => part.length > 0 && part !== '.' && part !== '..');

    if (
        typeof finding.fingerprint !== 'string'
        || typeof finding.ruleId !== 'string' || !finding.ruleId
        || !safeFile
        || typeof finding.container !== 'string' || !finding.container
        || !validHash(finding.statementHash)
        || (finding.flowHash !== null && !validHash(finding.flowHash))
        || !Number.isInteger(finding.lineHint) || (finding.lineHint as number) < 1
        || !Number.isInteger(finding.columnHint) || (finding.columnHint as number) < 1
    ) return false;

    const calculated = fingerprintFor({
        ruleId: finding.ruleId as string,
        file,
        container: finding.container as string,
        statementHash: finding.statementHash as string,
        flowHash: finding.flowHash as string | null,
    });
    return calculated === finding.fingerprint;
};

const parseFindings = (value: unknown, source: string) => {
    if (!Array.isArray(value) || !value.every(isFindingIdentity)) {
        throw new Error(`${source} does not contain a valid findings array.`);
    }
    return value as FindingIdentity[];
};

export const createScanArtifact = (
    pluginId: string,
    repositoryUrl: string,
    commitHash: string,
    issueNumber: number,
    runId: number,
    findings: FingerprintedSarifResult[],
): ScanFindingsArtifact => {
    assertValidPluginId(pluginId);
    if (!/^[a-fA-F0-9]{40}$/.test(commitHash)) throw new Error('Scan artifact commit hash is invalid.');
    if (!Number.isInteger(issueNumber) || issueNumber < 1) throw new Error('Scan artifact issue number is invalid.');
    if (!Number.isInteger(runId) || runId < 1) throw new Error('Scan artifact run ID is invalid.');

    return {
        schemaVersion: approvedFindingsSchemaVersion,
        pluginId,
        repositoryUrl: normalizeRepositoryUrl(repositoryUrl),
        commitHash: commitHash.toLowerCase(),
        issueNumber,
        runId,
        generatedAt: new Date().toISOString(),
        findings: findings.map(finding => finding.identity),
    };
};

export const writeScanArtifact = async (artifactPath: string, artifact: ScanFindingsArtifact) => {
    await mkdir(dirname(artifactPath), { recursive: true });
    await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
};

export const readScanArtifact = async (artifactPath: string): Promise<ScanFindingsArtifact> => {
    const parsed: unknown = JSON.parse(await readFile(artifactPath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Scan findings artifact must contain an object.');
    }

    const artifact = parsed as Record<string, unknown>;
    if (
        artifact.schemaVersion !== approvedFindingsSchemaVersion
        || typeof artifact.pluginId !== 'string'
        || typeof artifact.repositoryUrl !== 'string'
        || typeof artifact.commitHash !== 'string'
        || !Number.isInteger(artifact.issueNumber) || (artifact.issueNumber as number) < 1
        || !Number.isInteger(artifact.runId) || (artifact.runId as number) < 1
        || typeof artifact.generatedAt !== 'string' || Number.isNaN(Date.parse(artifact.generatedAt))
    ) {
        throw new Error('Scan findings artifact metadata is malformed or uses an unsupported schema.');
    }

    assertValidPluginId(artifact.pluginId);
    if (!/^[a-f0-9]{40}$/.test(artifact.commitHash)) throw new Error('Scan findings artifact commit hash is invalid.');
    const findings = parseFindings(artifact.findings, 'Scan findings artifact');

    return { ...(artifact as unknown as ScanFindingsArtifact), findings };
};

export const readApprovedBaseline = async (
    registryRoot: string,
    pluginId: string,
    repositoryUrl: string,
): Promise<ApprovedFindingsBaseline | null> => {
    const path = baselinePathFor(registryRoot, pluginId);
    if (!(await exists(path))) return null;

    const parsed: unknown = JSON.parse(await readFile(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error(`Approved-findings baseline for ${pluginId} must contain an object.`);
    }

    const baseline = parsed as Record<string, unknown>;
    const approvedScan = baseline.approvedScan as Record<string, unknown> | null;
    if (
        baseline.schemaVersion !== approvedFindingsSchemaVersion
        || baseline.pluginId !== pluginId
        || typeof baseline.repositoryUrl !== 'string'
        || normalizeRepositoryUrl(baseline.repositoryUrl) !== normalizeRepositoryUrl(repositoryUrl)
        || !approvedScan
        || typeof approvedScan.commitHash !== 'string' || !/^[a-f0-9]{40}$/.test(approvedScan.commitHash)
        || !Number.isInteger(approvedScan.issueNumber) || (approvedScan.issueNumber as number) < 1
        || !Number.isInteger(approvedScan.runId) || (approvedScan.runId as number) < 1
        || typeof approvedScan.approvedBy !== 'string' || !approvedScan.approvedBy.trim()
        || typeof approvedScan.approvedAt !== 'string' || Number.isNaN(Date.parse(approvedScan.approvedAt))
    ) {
        throw new Error(`Approved-findings baseline metadata for ${pluginId} is malformed or belongs to another repository.`);
    }

    const findings = parseFindings(baseline.findings, `Approved-findings baseline for ${pluginId}`);
    return { ...(baseline as unknown as ApprovedFindingsBaseline), findings };
};

export const classifyFindings = (
    current: FingerprintedSarifResult[],
    baseline: ApprovedFindingsBaseline | null,
) => {
    const currentCounts = new Map<string, number>();
    const baselineCounts = new Map<string, number>();

    for (const finding of current) {
        currentCounts.set(finding.identity.fingerprint, (currentCounts.get(finding.identity.fingerprint) ?? 0) + 1);
    }
    for (const finding of baseline?.findings ?? []) {
        baselineCounts.set(finding.fingerprint, (baselineCounts.get(finding.fingerprint) ?? 0) + 1);
    }

    const approvedEarlier: FingerprintedSarifResult[] = [];
    const requiringReview: FingerprintedSarifResult[] = [];
    for (const finding of current) {
        const fingerprint = finding.identity.fingerprint;
        if (currentCounts.get(fingerprint) === 1 && baselineCounts.get(fingerprint) === 1) {
            approvedEarlier.push(finding);
        } else {
            requiringReview.push(finding);
        }
    }

    return { requiringReview, approvedEarlier };
};

export interface ExpectedScanArtifact {
    pluginId: string;
    repositoryUrl: string;
    commitHash: string;
    issueNumber: number;
    runId: number;
}

export const validateScanArtifact = (artifact: ScanFindingsArtifact, expected: ExpectedScanArtifact) => {
    assertValidPluginId(expected.pluginId);
    if (artifact.pluginId !== expected.pluginId) throw new Error('Scan artifact plugin ID does not match the published manifest.');
    if (normalizeRepositoryUrl(artifact.repositoryUrl) !== normalizeRepositoryUrl(expected.repositoryUrl)) {
        throw new Error('Scan artifact repository URL does not match the approved submission.');
    }
    if (artifact.commitHash !== expected.commitHash.toLowerCase()) throw new Error('Scan artifact commit does not match the approved submission.');
    if (artifact.issueNumber !== expected.issueNumber) throw new Error('Scan artifact issue number does not match the approval event.');
    if (artifact.runId !== expected.runId) throw new Error('Scan artifact run ID does not match the completed report.');

    const counts = new Map<string, number>();
    for (const finding of artifact.findings) {
        counts.set(finding.fingerprint, (counts.get(finding.fingerprint) ?? 0) + 1);
    }
    const duplicate = [...counts.entries()].find(([, count]) => count > 1);
    if (duplicate) {
        throw new Error(`Scan artifact contains an ambiguous duplicate finding (${duplicate[0]}).`);
    }
};

export const replaceApprovedBaseline = async (
    registryRoot: string,
    artifact: ScanFindingsArtifact,
    expected: ExpectedScanArtifact,
    approvedBy: string,
    approvedAt: string,
) => {
    validateScanArtifact(artifact, expected);
    if (!approvedBy.trim()) throw new Error('Approval actor is required.');
    if (Number.isNaN(Date.parse(approvedAt))) throw new Error('Approval timestamp is invalid.');

    const path = baselinePathFor(registryRoot, expected.pluginId);
    if (artifact.findings.length === 0) {
        await unlink(path).catch(error => {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        });
        return { path, removed: true, findingCount: 0 };
    }

    const baseline: ApprovedFindingsBaseline = {
        schemaVersion: approvedFindingsSchemaVersion,
        pluginId: expected.pluginId,
        repositoryUrl: normalizeRepositoryUrl(expected.repositoryUrl),
        approvedScan: {
            commitHash: expected.commitHash.toLowerCase(),
            issueNumber: expected.issueNumber,
            runId: expected.runId,
            approvedBy,
            approvedAt,
        },
        findings: artifact.findings,
    };

    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
    return { path, removed: false, findingCount: artifact.findings.length };
};
