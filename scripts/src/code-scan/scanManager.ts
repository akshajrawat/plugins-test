import { readFile, readdir, stat } from 'fs/promises';
import { join, relative, resolve, sep } from 'path';
import {
    extractReportMetadata,
    getPhases,
    renderFinalReport,
    runUrlFor,
    statusTemplate,
} from './scanReport';
import type {
    GithubApiContext,
    GithubContext,
} from '../types/types';
import { updateComment, failWithIssueComment } from '../utils/github';
import { parseIssuePayload } from '../utils/payload';
import { fileExists } from '../utils/utils';

const ignoredSourceDirectories = new Set([
    '.git',
    '.github',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'out',
    'test',
    'tests',
]);

const sourceFilePattern = /\.(cjs|cts|js|jsx|mjs|mts|ts|tsx)$/i;

const canonicalRepositoryUrl = (url: string) => {
    return url.trim().replace(/\/+$/, '').replace(/\.git$/i, '');
};

const normalizeUrl = (url: string) => {
    return canonicalRepositoryUrl(url).toLowerCase();
};

const repoNameFromUrl = (repositoryUrl: string) => {
    const urlParts = normalizeUrl(repositoryUrl).split('/');
    return urlParts.slice(-2).join('/');
};

const validateTitle = (title: string | null | undefined) => {
    const titleRegex = /^\[Plugin Submission\]\s+.+\s+v[0-9.]+.*$/;

    if (titleRegex.test(title ?? '')) return '';

    return 'Invalid issue title format. It must begin with [Plugin Submission] and include the plugin name and version.';
};

// Gets the path to manifest.json
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

// checks if the plugin already exists in the manifest.json
const existingPluginFor = async (pluginName: string) => {
    const manifestsPath = await getRegistryPath('manifests.json');

    if (!(await fileExists(manifestsPath))) return null;

    const manifests = JSON.parse(await readFile(manifestsPath, 'utf8'));
    const directlyRegisteredPlugin = manifests[pluginName];

    if (directlyRegisteredPlugin) return directlyRegisteredPlugin;

    for (const pluginId in manifests) {
        const plugin = manifests[pluginId];

        if (plugin.name === pluginName) return plugin;
    }

    return null;
};

const closeOwnershipMismatchIssue = async (
    { github, context, core }: GithubContext,
    commentId: number,
    commentBody: string,
    pluginName: string,
    registeredUrl: string,
    repositoryUrl: string,
) => {
    const rejectMsg = `Security reject: plugin ${pluginName} already exists, but the repository URL does not match the registered owner.
Expected: ${registeredUrl}
Provided: ${repositoryUrl}`;

    const body = `${commentBody}

${rejectMsg}`;

    await updateComment(github, context, commentId, body);

    await github.rest.issues.update({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        state: 'closed',
    });

    core.setOutput('handled_failure', 'true');
    core.setFailed('Ownership mismatch. Issue closed.');
};

const isInside = (parent: string, child: string) => {
    const relativePath = relative(parent, child);
    return relativePath === '' || (!relativePath.startsWith('..') && !relativePath.startsWith(sep));
};

const findSourceFiles = async (root: string) => {
    const files: string[] = [];

    const visit = async (directory: string) => {
        const entries = await readdir(directory, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (!ignoredSourceDirectories.has(entry.name)) {
                    await visit(join(directory, entry.name));
                }

                continue;
            }

            if (entry.isFile() && sourceFilePattern.test(entry.name)) {
                files.push(join(directory, entry.name));
            }
        }
    };

    await visit(root);

    return files;
};

// Created a comment in the issue body to indicate the scanning workflow has been started 
export const acknowledgeScanInitialization = async ({ github, context }: GithubContext) => {
    const body = `# Security Scan Initializing
Setting up the scanner and validating the submission payload.`;
    const comment = await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: body,
    });

    return comment.data.id;
};

// Checks if the title contains `[Plugin Submission]`
// Checks if the issue body is in perfect form 
export const preflightMetadataValidation = async ({ github, context, core }: GithubContext) => {
    const titleError = validateTitle(context.payload.issue.title);

    if (titleError) {
        return await failWithIssueComment(
            { github, context, core },
            process.env.ACK_COMMENT_ID,
            'Security Scan Rejected',
            titleError,
        );
    }

    const validation = parseIssuePayload(context.payload.issue.body);

    if ('error' in validation) {
        return await failWithIssueComment(
            { github, context, core },
            process.env.ACK_COMMENT_ID,
            'Security Scan Rejected',
            validation.error,
        );
    }

    core.setOutput('handled_failure', 'false');

    return { should_proceed: true };
};


export const initialize = async ({ github, context, core }: GithubContext) => {
    const validation = parseIssuePayload(context.payload.issue.body);
    const initialCommentId = process.env.INITIAL_COMMENT_ID;

    if ('error' in validation) {
        return await failWithIssueComment(
            { github, context, core },
            initialCommentId,
            'Security Scan Failed',
            validation.error,
        );
    }

    const { plugin_name, repository_url, commit_hash } = validation.payload;
    const runUrl = runUrlFor(context);
    const phases = getPhases(1);
    const commentBody = statusTemplate(repository_url, commit_hash, runUrl, phases);

    // Update or create the comment in the body 
    const comment = initialCommentId
        ? await github.rest.issues.updateComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            comment_id: parseInt(initialCommentId, 10),
            body: commentBody,
        })
        : await github.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.issue.number,
            body: commentBody,
        });

    const existingPlugin = await existingPluginFor(plugin_name);
    const registeredUrl = existingPlugin?.repository_url;

    if (registeredUrl && normalizeUrl(registeredUrl) !== normalizeUrl(repository_url)) {
        await closeOwnershipMismatchIssue(
            { github, context, core },
            comment.data.id,
            commentBody,
            plugin_name,
            registeredUrl,
            repository_url,
        );

        return { should_proceed: false };
    }

    const repoName = repoNameFromUrl(repository_url);

    core.setOutput('repository_url', repository_url);
    core.setOutput('commit_hash', commit_hash);
    core.setOutput('repo_name', repoName);
    core.setOutput('comment_id', comment.data.id.toString());
    core.setOutput('should_proceed', 'true');
    core.setOutput('handled_failure', 'false');

    return {
        repository_url,
        commit_hash,
        repo_name: repoName,
        comment_id: comment.data.id,
        should_proceed: true,
    };
};

export const updatePhase = async ({ github, context }: GithubApiContext, commentId: string, phase: number) => {
    const comment = await github.rest.issues.getComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: parseInt(commentId, 10),
    });
    const metadata = extractReportMetadata(comment.data.body);
    const phases = getPhases(phase);
    const newHeader = statusTemplate(metadata.repoUrl, metadata.commitHash, metadata.runUrl, phases);

    await updateComment(github, context, commentId, newHeader);
};

export const validateTargetRepository = async (
    { github, context, core }: GithubContext,
    commentId: string,
    targetPath: string,
) => {
    const workspace = process.env.GITHUB_WORKSPACE ? resolve(process.env.GITHUB_WORKSPACE) : resolve(process.cwd());
    const targetRoot = resolve(workspace, targetPath);

    const isDir = await stat(targetRoot).then(s => s.isDirectory()).catch(() => false);

    if (!isInside(workspace, targetRoot) || !isDir) {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Failed',
            `Target repository path is invalid: ${targetPath}`,
        );
    }

    const parsePayloadResult = parseIssuePayload(context.payload.issue.body);
    if (!parsePayloadResult.ok) {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Failed',
            'Could not parse payload during target validation.',
        );
    }

    const { plugin_name, repository_url } = parsePayloadResult.payload;
    const packagePath = resolve(targetRoot, 'package.json');
    let manifestPath = resolve(targetRoot, 'src', 'manifest.json');
    if (!(await fileExists(manifestPath))) {
        manifestPath = resolve(targetRoot, 'manifest.json');
    }

    if (await fileExists(packagePath)) {
        try {
            const packageContent = await readFile(packagePath, 'utf8');
            const pkg = JSON.parse(packageContent);

            if (pkg.name !== plugin_name) {
                return await failWithIssueComment(
                    { github, context, core },
                    commentId,
                    'Security Scan Rejected',
                    `The plugin name in the issue payload (${plugin_name}) does not match the name in the repository's package.json (${pkg.name || 'unknown'}).`,
                );
            }
        } catch (e) {
            return await failWithIssueComment(
                { github, context, core },
                commentId,
                'Security Scan Failed',
                `Failed to parse package.json: ${e instanceof Error ? e.message : String(e)}`,
            );
        }
    } else {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Rejected',
            'Could not find package.json in the target repository root.',
        );
    }

    if (await fileExists(manifestPath)) {
        try {
            const manifestContent = await readFile(manifestPath, 'utf8');
            const manifest = JSON.parse(manifestContent);

            const manifestRepo = manifest.repository_url || manifest.repository;
            if (manifestRepo) {
                const rawManifestUrl = typeof manifestRepo === 'string' ? manifestRepo : (manifestRepo.url || '');
                const normalizedManifestUrl = normalizeUrl(rawManifestUrl);
                const normalizedPayloadUrl = normalizeUrl(repository_url);

                if (normalizedManifestUrl && normalizedPayloadUrl && normalizedManifestUrl !== normalizedPayloadUrl) {
                    return await failWithIssueComment(
                        { github, context, core },
                        commentId,
                        'Security Scan Rejected',
                        `The repository URL in the issue payload (${repository_url}) does not match the repository URL in the manifest.json (${rawManifestUrl}).`,
                    );
                }
            }
        } catch (e) {
            return await failWithIssueComment(
                { github, context, core },
                commentId,
                'Security Scan Failed',
                `Failed to parse manifest.json: ${e instanceof Error ? e.message : String(e)}`,
            );
        }
    } else {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Rejected',
            'Could not find manifest.json in the target repository root or src/ directory.',
        );
    }

    const sourceFiles = await findSourceFiles(targetRoot);

    if (sourceFiles.length === 0) {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Rejected',
            'The target repository does not contain JavaScript or TypeScript source files outside generated/test directories.',
        );
    }

    core.setOutput('source_file_count', sourceFiles.length.toString());
    core.setOutput('handled_failure', 'false');

    return { source_file_count: sourceFiles.length };
};

export const generateFinalReport = async (
    { github, context }: GithubApiContext,
    commentId: string,
    sarifPath: string,
    repoUrl: string,
    commitHash: string,
) => {
    const body = await renderFinalReport({
        sarifPath,
        repoUrl,
        commitHash,
        runUrl: runUrlFor(context),
    });

    await updateComment(github, context, commentId, body);
};

export const handleWorkflowFailure = async ({ github, context }: GithubApiContext, commentId: string) => {
    await updateComment(
        github,
        context,
        commentId,
        `# Security Scan Failed

The workflow encountered a system error before it could complete.

**Workflow Run:** [View Logs](${runUrlFor(context)})`,
    );
};
