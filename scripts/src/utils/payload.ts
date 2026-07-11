import type { SubmissionPayload, ValidationResult } from '../types/types';

export const parseGithubRepository = (repositoryUrl: string) => {
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

export const canonicalRepositoryUrl = (repositoryUrl: string) => {
    const repository = parseGithubRepository(repositoryUrl);
    return repository ? repository.canonicalUrl : repositoryUrl.trim().replace(/\/+$/, '').replace(/\.git$/i, '');
};

export const normalizeRepositoryUrl = (repositoryUrl: string) => {
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
