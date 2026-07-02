import {
    existsSync,
    readFileSync,
    readdirSync,
    statSync,
} from 'fs';
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
    SubmissionPayload,
    ValidationResult,
} from './types';

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

const updateComment = async (github: any, context: any, commentId: string | number, body: string) => {
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: typeof commentId === 'number' ? commentId : parseInt(commentId, 10),
        body,
    });
};

const failWithIssueComment = async (
    { github, context, core }: GithubContext,
    commentId: string | undefined,
    heading: string,
    message: string,
) => {
    if (commentId) {
        const body = `
            # ${heading}
            ${message}
            **Workflow Run:** [View Logs](${runUrlFor(context)})
            `
        await updateComment(github, context, commentId, body);
    }

    core.setOutput('handled_failure', 'true');
    core.setFailed(message);

    return { should_proceed: false };
};

// Parse the issue body to find the JSON block and relavent meta data
// Checks if all the data is in correct form and returns the payload
const parseIssuePayload = (body: string | null | undefined): ValidationResult => {
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

    const urlRegex = /^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(\.git)?\/?$/;

    if (!urlRegex.test(repository_url)) {
        return {
            ok: false,
            error: `Invalid repository URL: ${repository_url}. It must be a GitHub repository URL.`,
        };
    }

    const hashRegex = /^[a-fA-F0-9]{40}$/;

    if (!hashRegex.test(commit_hash)) {
        return {
            ok: false,
            error: `Invalid commit hash: ${commit_hash}.`,
        };
    }

    return {
        ok: true,
        payload: {
            plugin_name,
            repository_url: canonicalRepositoryUrl(repository_url),
            commit_hash,
        },
    };
};

const validateTitle = (title: string | null | undefined) => {
    const titleRegex = /^\[Plugin Submission\]\s+.+\s+v[0-9.]+.*$/;

    if (titleRegex.test(title ?? '')) return '';

    return 'Invalid issue title format. It must begin with [Plugin Submission] and include the plugin name and version.';
};

// Gets the path to manifest.json
const getRegistryPath = (relativePath: string) => {
    const workspace = process.env.GITHUB_WORKSPACE;
    const candidates = [
        workspace ? resolve(workspace, 'plugins-test', relativePath) : '',
        resolve(process.cwd(), 'plugins-test', relativePath),
        resolve(process.cwd(), relativePath),
        resolve(__dirname, '..', '..', relativePath),
    ].filter(Boolean);

    return candidates.find(candidate => existsSync(candidate)) ?? candidates[0];
};

// checks if the plugin already exists in the manifest.json
const existingPluginFor = (pluginName: string) => {
    const manifestsPath = getRegistryPath('manifests.json');

    if (!existsSync(manifestsPath)) return null;

    const manifests = JSON.parse(readFileSync(manifestsPath, 'utf8'));
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
    const rejectMsg = `
    Security reject: plugin ${pluginName} already exists, but the repository URL does not match the registered owner.
    Expected: ${registeredUrl}
    Provided: ${repositoryUrl}
    `;

    const body = `
    ${commentBody}
    ${rejectMsg}
    `

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

const findSourceFiles = (root: string) => {
    const files: string[] = [];

    const visit = (directory: string) => {
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
            if (entry.isDirectory()) {
                if (!ignoredSourceDirectories.has(entry.name)) {
                    visit(join(directory, entry.name));
                }

                continue;
            }

            if (entry.isFile() && sourceFilePattern.test(entry.name)) {
                files.push(join(directory, entry.name));
            }
        }
    };

    visit(root);

    return files;
};

// Created a comment in the issue body to indicate the scanning workflow has been started 
export const acknowledgeScanInitialization = async ({ github, context }: GithubContext) => {
    const body = `
    # Security Scan Initializing
    Setting up the scanner and validating the submission payload.
    `
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

    const existingPlugin = existingPluginFor(plugin_name);
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

    if (!isInside(workspace, targetRoot) || !existsSync(targetRoot) || !statSync(targetRoot).isDirectory()) {
        return await failWithIssueComment(
            { github, context, core },
            commentId,
            'Security Scan Failed',
            `Target repository path is invalid: ${targetPath}`,
        );
    }

    const sourceFiles = findSourceFiles(targetRoot);

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
    const body = renderFinalReport({
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
