import type { GithubContext, ValidationResult } from '../code-scan/types';
import type { PublishPayload, PublishSummary } from './types';

export const runUrlFor = async (context: any) => {
    const serverUrl = context.serverUrl ?? 'https://github.com';
    return `${serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
};

export const parseGithubRepository = async (repositoryUrl: string) => {
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

export const canonicalRepositoryUrl = async (repositoryUrl: string) => {
    const repository = await parseGithubRepository(repositoryUrl);
    return repository ? repository.canonicalUrl : repositoryUrl.trim().replace(/\/+$/, '').replace(/\.git$/i, '');
};

export const normalizeRepositoryUrl = async (repositoryUrl: string) => {
    const canonical = await canonicalRepositoryUrl(repositoryUrl);
    return canonical.toLowerCase();
};

export const commentIdNumber = async (commentId: string | number) => {
    const id = typeof commentId === 'number' ? commentId : Number.parseInt(commentId, 10);
    if (!Number.isInteger(id)) throw new Error(`Invalid issue comment id: ${commentId}`);
    return id;
};

export const updateComment = async (github: any, context: any, commentId: string | number, body: string) => {
    const id = await commentIdNumber(commentId);
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: id,
        body,
    });
};
