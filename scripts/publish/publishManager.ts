import { createHash } from 'crypto';
import { access, readFile, writeFile } from 'fs/promises';
import { join, resolve } from 'path';
import type { GithubContext, SubmissionPayload, ValidationResult } from '../code-scan/types';

interface PublishPayload extends SubmissionPayload {
    repo_name: string;
}

interface PublishSummary {
    pluginId?: string;
    pluginVersion?: string;
    pluginDirectory?: string;
    registryUpdated?: boolean;
    readmeUpdated?: boolean;
    statsUpdated?: boolean;
    releaseUpdated?: boolean;
}

const phaseCount = 6;

const fileExists = async (path: string) => {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
};

const escapeMarkdownText = (value: string) => {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
};

const escapeInlineCode = (value: string) => {
    return value.replace(/`/g, '\\`');
};

const escapeMarkdownUrl = (value: string) => {
    return value.replace(/\(/g, '%28').replace(/\)/g, '%29');
};

const runUrlFor = (context: any) => {
    const serverUrl = context.serverUrl ?? 'https://github.com';
    return `${serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
};

const statusLabel = (phase: number, currentPhase: number) => {
    if (phase < currentPhase) return '✅';
    if (phase === currentPhase) return '⏳';
    return '⚪';
};

const getPhases = (currentPhase: number) => {
    const phases: Record<number, string> = {};

    for (let phase = 1; phase <= phaseCount; phase++) {
        phases[phase] = statusLabel(phase, currentPhase);
    }

    if (currentPhase > phaseCount) {
        for (let phase = 1; phase <= phaseCount; phase++) {
            phases[phase] = '✅';
        }
    }

    return phases;
};

const parseGithubRepository = (repositoryUrl: string) => {
    const match = repositoryUrl.trim().match(
        /^https?:\/\/(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git)?\/?$/,
    );

    if (!match) return null;

    const owner = match[1];
    const repo = match[2];

    return {
        canonicalUrl: `https://github.com/${owner}/${repo}`,
        repoName: `${owner}/${repo}`,
    };
};

const canonicalRepositoryUrl = (repositoryUrl: string) => {
    const repository = parseGithubRepository(repositoryUrl);
    return repository ? repository.canonicalUrl : repositoryUrl.trim().replace(/\/+$/, '').replace(/\.git$/i, '');
};

const normalizeRepositoryUrl = (repositoryUrl: string) => {
    return canonicalRepositoryUrl(repositoryUrl).toLowerCase();
};

export const parseIssuePayload = (body: string | null | undefined): ValidationResult => {
    const jsonMatch = (body ?? '').match(/```json\s*([\s\S]*?)\s*```/);

    if (!jsonMatch) {
        return {
            ok: false,
            error: 'Could not find a JSON payload in the issue body. Include a ```json block.',
        };
    }

    let payload: Partial<SubmissionPayload>;

    try {
        payload = JSON.parse(jsonMatch[1]) as Partial<SubmissionPayload>;
    } catch {
        return {
            ok: false,
            error: 'Invalid JSON payload. Check the JSON block for syntax errors.',
        };
    }

    const { plugin_name, repository_url, commit_hash } = payload;

    if (!plugin_name || !repository_url || !commit_hash) {
        return {
            ok: false,
            error: 'Missing required fields. Provide plugin_name, repository_url, and commit_hash.',
        };
    }

    const repository = parseGithubRepository(repository_url);

    if (!repository) {
        return {
            ok: false,
            error: `Invalid repository URL: ${repository_url}. It must be a GitHub repository URL.`,
        };
    }

    if (!/^[a-fA-F0-9]{40}$/.test(commit_hash)) {
        return {
            ok: false,
            error: `Invalid commit hash: ${commit_hash}.`,
        };
    }

    return {
        ok: true,
        payload: {
            plugin_name,
            repository_url: repository.canonicalUrl,
            commit_hash,
        },
    };
};

const getRegistryPath = async (relativePath: string) => {
    const workspace = process.env.GITHUB_WORKSPACE;
    const candidates = [
        workspace ? resolve(workspace, 'plugins-test', relativePath) : '',
        resolve(process.cwd(), 'plugins-test', relativePath),
        resolve(process.cwd(), relativePath),
        resolve(__dirname, '..', '..', relativePath),
    ].filter(Boolean);

    for (const candidate of candidates) {
        if (await fileExists(candidate)) return candidate;
    }

    return candidates[0];
};

const readJsonFile = async <T>(path: string, defaultValue: T): Promise<T> => {
    if (!(await fileExists(path))) return defaultValue;
    return JSON.parse(await readFile(path, 'utf8')) as T;
};

const existingPluginFor = async (pluginName: string) => {
    const manifestsPath = await getRegistryPath('manifests.json');
    const manifests = await readJsonFile<Record<string, any>>(manifestsPath, {});
    const directlyRegisteredPlugin = manifests[pluginName];

    if (directlyRegisteredPlugin) return directlyRegisteredPlugin;

    for (const pluginId in manifests) {
        const plugin = manifests[pluginId];
        if (plugin.name === pluginName) return plugin;
    }

    return null;
};

const validateRegistryOwnership = async (payload: PublishPayload) => {
    const existingPlugin = await existingPluginFor(payload.plugin_name);
    const registeredUrl = existingPlugin?.repository_url;

    if (registeredUrl && normalizeRepositoryUrl(registeredUrl) !== normalizeRepositoryUrl(payload.repository_url)) {
        return `Security reject: plugin ${payload.plugin_name} already exists, but the repository URL does not match the registered owner.
Expected: ${registeredUrl}
Provided: ${payload.repository_url}`;
    }

    return '';
};

const scanReportMatchesPayload = (body: string, payload: PublishPayload) => {
    if (!body.includes('# Security Scan Report') || !body.includes('# Findings')) return false;
    if (body.includes('Failed to generate a SARIF report') || body.includes('# Security Scan Failed')) return false;

    const targetUrlMatch = body.match(/\*\*Target:\*\* \[[^\]]+\]\(([^)]+)\)/);
    const targetUrl = targetUrlMatch?.[1] ?? '';
    const targetMatch = targetUrl.match(/^(.*)\/(?:tree|commit)\/([a-fA-F0-9]{40})(?:[)#?].*)?$/);

    if (!targetMatch) return false;

    const scannedRepoUrl = targetMatch[1];
    const scannedCommitHash = targetMatch[2].toLowerCase();

    return normalizeRepositoryUrl(scannedRepoUrl) === normalizeRepositoryUrl(payload.repository_url)
        && scannedCommitHash === payload.commit_hash.toLowerCase();
};

const hasCompletedScanReport = async ({ github, context }: GithubContext, payload: PublishPayload) => {
    const comments = await github.paginate(github.rest.issues.listComments, {
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        per_page: 100,
    });

    return comments.some((comment: any) => scanReportMatchesPayload(comment.body ?? '', payload));
};

const toPublishPayload = (payload: SubmissionPayload): PublishPayload => {
    const repository = parseGithubRepository(payload.repository_url);
    if (!repository) throw new Error(`Invalid repository URL: ${payload.repository_url}`);

    return {
        ...payload,
        repository_url: repository.canonicalUrl,
        repo_name: repository.repoName,
    };
};

const parsePayloadFromContext = (context: any): PublishPayload | null => {
    const validation = parseIssuePayload(context.payload.issue.body);
    if (!validation.ok) return null;
    return toPublishPayload(validation.payload);
};

const commentIdNumber = (commentId: string | number) => {
    const id = typeof commentId === 'number' ? commentId : Number.parseInt(commentId, 10);
    if (!Number.isInteger(id)) throw new Error(`Invalid issue comment id: ${commentId}`);
    return id;
};

const updateComment = async (github: any, context: any, commentId: string | number, body: string) => {
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: commentIdNumber(commentId),
        body,
    });
};

const statusTemplate = (
    payload: PublishPayload,
    runUrl: string,
    currentPhase: number,
    details?: string,
) => {
    const phases = getPhases(currentPhase);
    const targetText = escapeMarkdownText(`${payload.repository_url}/tree/${payload.commit_hash}`);
    const targetUrl = escapeMarkdownUrl(`${payload.repository_url}/tree/${payload.commit_hash}`);
    const workflowRunUrl = escapeMarkdownUrl(runUrl);
    const detailBlock = details ? `\n\n${escapeMarkdownText(details)}` : '';

    return `# Plugin Publish Status
**Plugin:** ${escapeMarkdownText(payload.plugin_name)}
**Target:** [${targetText}](${targetUrl})
**Workflow Run:** [View Logs](${workflowRunUrl})${detailBlock}

# Pipeline Status
* ${phases[1]} **Phase 1: Validate approved submission**
* ${phases[2]} **Phase 2: Build plugin artifact**
* ${phases[3]} **Phase 3: Download compiled artifact**
* ${phases[4]} **Phase 4: Publish registry files**
* ${phases[5]} **Phase 5: Update GitHub release and stats**
* ${phases[6]} **Phase 6: Commit registry update**`;
};

const failureTemplate = (heading: string, message: string, runUrl: string) => {
    return `# ${heading}

${escapeMarkdownText(message)}

**Workflow Run:** [View Logs](${escapeMarkdownUrl(runUrl)})`;
};

export const acknowledgePublishInitialization = async ({ github, context, core }: GithubContext) => {
    const initialBody = `# Plugin Publish Status
Validating the approved submission.

**Workflow Run:** [View Logs](${escapeMarkdownUrl(runUrlFor(context))})`;
    const initialCommentId = process.env.INITIAL_COMMENT_ID;
    const commentId = initialCommentId
        ? initialCommentId
        : (await github.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.issue.number,
            body: initialBody,
        })).data.id.toString();

    if (initialCommentId) {
        await updateComment(github, context, initialCommentId, initialBody);
    }

    core.setOutput('comment_id', commentId.toString());

    const validation = parseIssuePayload(context.payload.issue.body);

    if ('error' in validation) {
        await updateComment(
            github,
            context,
            commentId,
            failureTemplate('Plugin Publish Rejected', validation.error, runUrlFor(context)),
        );

        core.setOutput('should_proceed', 'false');
        core.setFailed(validation.error);

        return { should_proceed: false, comment_id: commentId.toString() };
    }

    const payload = toPublishPayload(validation.payload);
    const ownershipError = await validateRegistryOwnership(payload);

    if (ownershipError) {
        await updateComment(
            github,
            context,
            commentId,
            failureTemplate('Plugin Publish Rejected', ownershipError, runUrlFor(context)),
        );

        core.setOutput('should_proceed', 'false');
        core.setFailed(ownershipError);

        return { should_proceed: false, comment_id: commentId.toString() };
    }

    if (!(await hasCompletedScanReport({ github, context, core }, payload))) {
        const scanError = 'No completed security scan report was found for this exact repository URL and commit hash. Re-run the scan before approving this submission.';

        await updateComment(
            github,
            context,
            commentId,
            failureTemplate('Plugin Publish Rejected', scanError, runUrlFor(context)),
        );

        core.setOutput('should_proceed', 'false');
        core.setFailed(scanError);

        return { should_proceed: false, comment_id: commentId.toString() };
    }

    await updateComment(
        github,
        context,
        commentId,
        statusTemplate(payload, runUrlFor(context), 2, 'Approved submission validated. The untrusted build job is starting.'),
    );

    core.setOutput('plugin_name', payload.plugin_name);
    core.setOutput('repository_url', payload.repository_url);
    core.setOutput('repo_name', payload.repo_name);
    core.setOutput('commit_hash', payload.commit_hash);
    core.setOutput('comment_id', commentId.toString());
    core.setOutput('should_proceed', 'true');

    return {
        plugin_name: payload.plugin_name,
        repository_url: payload.repository_url,
        repo_name: payload.repo_name,
        commit_hash: payload.commit_hash,
        comment_id: commentId.toString(),
        should_proceed: true,
    };
};

export const updatePublishPhase = async (
    { github, context }: GithubContext,
    commentId: string | number,
    phase: number,
    details?: string,
) => {
    const payload = parsePayloadFromContext(context);
    const body = payload
        ? statusTemplate(payload, runUrlFor(context), phase, details)
        : failureTemplate('Plugin Publish Status', details ?? 'Publish workflow is running.', runUrlFor(context));

    await updateComment(github, context, commentId, body);
};

const readJsonFromFile = async (path: string) => {
    return JSON.parse(await readFile(path, 'utf8'));
};

const sha256File = async (path: string) => {
    const hash = createHash('sha256');
    hash.update(await readFile(path));
    return `sha256:${hash.digest('hex')}`;
};

const commitHashFromPublishCommit = (publishCommit: unknown) => {
    if (typeof publishCommit !== 'string') return '';
    return publishCommit.includes(':') ? publishCommit.split(':').pop() ?? '' : publishCommit;
};

const writeJsonFile = async (path: string, value: unknown) => {
    await writeFile(path, `${JSON.stringify(value, null, '\t')}\n`, 'utf8');
};

export const markPublishedPluginApproved = async (repoDir: string, artifactManifestFile: string) => {
    const artifactManifest = await readJsonFromFile(artifactManifestFile);
    const pluginId = artifactManifest.id;

    if (!pluginId) {
        throw new Error('Artifact manifest is missing id.');
    }

    const registryManifestFile = join(repoDir, 'plugins', pluginId, 'manifest.json');
    const manifestsFile = join(repoDir, 'manifests.json');
    const registryManifest = await readJsonFromFile(registryManifestFile);
    const manifests = await readJsonFromFile(manifestsFile);

    registryManifest._approved = true;

    if (!manifests[pluginId]) {
        throw new Error(`manifests.json does not contain ${pluginId}.`);
    }

    manifests[pluginId]._approved = true;

    await writeJsonFile(registryManifestFile, registryManifest);
    await writeJsonFile(manifestsFile, manifests);

    return { plugin_id: pluginId };
};

export const verifyPublishedRegistry = async (
    { core }: GithubContext,
    repoDir: string,
    artifactManifestFile: string,
    artifactJplFile: string,
    expectedRepositoryUrl: string,
    expectedCommitHash: string,
) => {
    const artifactManifest = await readJsonFromFile(artifactManifestFile);
    const pluginId = artifactManifest.id;
    const pluginVersion = artifactManifest.version;

    if (!pluginId || !pluginVersion) {
        throw new Error('Artifact manifest is missing id or version.');
    }

    if (normalizeRepositoryUrl(artifactManifest.repository_url) !== normalizeRepositoryUrl(expectedRepositoryUrl)) {
        throw new Error(`Artifact repository_url does not match the approved issue payload for ${pluginId}.`);
    }

    const publishedCommitHash = commitHashFromPublishCommit(artifactManifest._publish_commit);
    if (publishedCommitHash.toLowerCase() !== expectedCommitHash.toLowerCase()) {
        throw new Error(`Artifact _publish_commit does not match the approved commit for ${pluginId}.`);
    }

    const artifactHash = await sha256File(artifactJplFile);
    if (artifactManifest._publish_hash !== artifactHash) {
        throw new Error(`Artifact _publish_hash does not match the compiled JPL bytes for ${pluginId}.`);
    }

    const registryManifestFile = join(repoDir, 'plugins', pluginId, 'manifest.json');
    const registryJplFile = join(repoDir, 'plugins', pluginId, 'plugin.jpl');
    const manifestsFile = join(repoDir, 'manifests.json');

    if (!(await fileExists(registryManifestFile))) {
        throw new Error(`Published registry manifest is missing: plugins/${pluginId}/manifest.json`);
    }

    if (!(await fileExists(registryJplFile))) {
        throw new Error(`Published plugin archive is missing: plugins/${pluginId}/plugin.jpl`);
    }

    const registryManifest = await readJsonFromFile(registryManifestFile);
    if (registryManifest.id !== pluginId || registryManifest.version !== pluginVersion) {
        throw new Error(`Published registry manifest does not match artifact identity for ${pluginId}.`);
    }

    if (registryManifest._approved !== true) {
        throw new Error(`Published registry manifest for ${pluginId} is missing _approved: true.`);
    }

    if (registryManifest._publish_hash !== artifactHash) {
        throw new Error(`Published registry manifest hash does not match the compiled JPL bytes for ${pluginId}.`);
    }

    if (normalizeRepositoryUrl(registryManifest.repository_url) !== normalizeRepositoryUrl(expectedRepositoryUrl)) {
        throw new Error(`Published registry manifest repository_url does not match the approved issue payload for ${pluginId}.`);
    }

    const manifests = await readJsonFromFile(manifestsFile);
    if (!manifests[pluginId]) {
        throw new Error(`manifests.json does not contain ${pluginId}.`);
    }

    if (manifests[pluginId]._approved !== true) {
        throw new Error(`manifests.json entry for ${pluginId} is missing _approved: true.`);
    }

    core.setOutput('plugin_id', pluginId);
    core.setOutput('plugin_version', pluginVersion);

    return { plugin_id: pluginId, plugin_version: pluginVersion };
};

const parseBoolean = (value: unknown) => {
    return value === true || value === 'true' || value === '1';
};

const parseSummary = (summaryJson: string | PublishSummary | null | undefined): PublishSummary => {
    if (!summaryJson) return {};
    if (typeof summaryJson !== 'string') return summaryJson;

    try {
        return JSON.parse(summaryJson) as PublishSummary;
    } catch {
        return {};
    }
};

export const summarizePublishResult = async (
    { core }: GithubContext,
    repoDir: string,
    manifestFile: string,
    releaseLogPath: string,
    readmeUpdated: string,
    statsUpdated: string,
) => {
    const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
    const pluginDirectory = join(repoDir, 'plugins', manifest.id);
    const pluginJplPath = join(pluginDirectory, 'plugin.jpl');
    const pluginManifestPath = join(pluginDirectory, 'manifest.json');
    const releaseLog = await fileExists(releaseLogPath) ? await readFile(releaseLogPath, 'utf8') : '';
    const releaseUpdated = /\b(Uploading|Deleting old asset)\b/.test(releaseLog);

    const summary: PublishSummary = {
        pluginId: manifest.id,
        pluginVersion: manifest.version,
        pluginDirectory: `plugins/${manifest.id}`,
        registryUpdated: await fileExists(pluginJplPath) && await fileExists(pluginManifestPath),
        readmeUpdated: parseBoolean(readmeUpdated),
        statsUpdated: parseBoolean(statsUpdated) || /Updating stats file/.test(releaseLog),
        releaseUpdated,
    };

    core.setOutput('summary', JSON.stringify(summary));
    return summary;
};

export const finishPublish = async (
    { github, context }: GithubContext,
    commentId: string | number,
    summaryJson?: string | PublishSummary,
) => {
    const payload = parsePayloadFromContext(context);
    const summary = parseSummary(summaryJson);
    const pluginLabel = summary.pluginId && summary.pluginVersion
        ? `${summary.pluginId}@${summary.pluginVersion}`
        : payload?.plugin_name ?? 'the plugin';
    const pluginDirectory = summary.pluginDirectory ?? (summary.pluginId ? `plugins/${summary.pluginId}` : 'plugins/');

    const body = `# Plugin Published Successfully

The plugin **${escapeMarkdownText(pluginLabel)}** has been added to the registry.

* Registry folder: \`${escapeInlineCode(pluginDirectory)}\` ${summary.registryUpdated ? 'updated' : 'not verified'}
* README.md: ${summary.readmeUpdated ? 'updated' : 'no file change detected'}
* GitHub release assets: ${summary.releaseUpdated ? 'updated' : 'no asset change detected'}
* stats.json: ${summary.statsUpdated ? 'updated' : 'no file change detected'}

**Workflow Run:** [View Logs](${escapeMarkdownUrl(runUrlFor(context))})`;

    await updateComment(github, context, commentId, body);

    await github.rest.issues.update({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        state: 'closed',
        state_reason: 'completed',
    });
};

export const handleWorkflowFailure = async (
    { github, context }: GithubContext,
    commentId: string | number | undefined,
    message = 'The publish workflow encountered an error. Check the workflow logs for details.',
) => {
    const body = failureTemplate('Plugin Publish Failed', message, runUrlFor(context));

    if (commentId) {
        await updateComment(github, context, commentId, body);
        return;
    }

    await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body,
    });
};
