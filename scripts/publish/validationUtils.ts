import type { SubmissionPayload, ValidationResult } from '../code-scan/types';
import type { PublishPayload, PublishSummary } from './types';
import { getRegistryPath, readJsonFile } from './fileUtils';
import { parseGithubRepository, normalizeRepositoryUrl } from './githubUtils';

export const parseIssuePayload = async (body: string | null | undefined): Promise<ValidationResult> => {
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

    const repository = await parseGithubRepository(repository_url);

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

export const existingPluginFor = async (pluginName: string) => {
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

export const validateRegistryOwnership = async (payload: PublishPayload) => {
    const existingPlugin = await existingPluginFor(payload.plugin_name);
    const registeredUrl = existingPlugin?.repository_url;

    if (registeredUrl) {
        const normalizedRegisteredUrl = await normalizeRepositoryUrl(registeredUrl);
        const normalizedPayloadUrl = await normalizeRepositoryUrl(payload.repository_url);
        
        if (normalizedRegisteredUrl !== normalizedPayloadUrl) {
            return `Security reject: plugin ${payload.plugin_name} already exists, but the repository URL does not match the registered owner.\nExpected: ${registeredUrl}\nProvided: ${payload.repository_url}`;
        }
    }

    return '';
};

export const toPublishPayload = async (payload: SubmissionPayload): Promise<PublishPayload> => {
    const repository = await parseGithubRepository(payload.repository_url);
    if (!repository) throw new Error(`Invalid repository URL: ${payload.repository_url}`);

    return {
        ...payload,
        repository_url: repository.canonicalUrl,
        repo_name: repository.repoName,
    };
};

export const parsePayloadFromContext = async (context: any): Promise<PublishPayload | null> => {
    const validation = await parseIssuePayload(context.payload.issue.body);
    if (!validation.ok) return null;
    return await toPublishPayload(validation.payload);
};

export const parseBoolean = async (value: unknown) => {
    return value === true || value === 'true' || value === '1';
};

export const parseSummary = async (summaryJson: string | PublishSummary | null | undefined): Promise<PublishSummary> => {
    if (!summaryJson) return {};
    if (typeof summaryJson !== 'string') return summaryJson;

    try {
        return JSON.parse(summaryJson) as PublishSummary;
    } catch {
        return {};
    }
};

export const commitHashFromPublishCommit = async (publishCommit: unknown) => {
    if (typeof publishCommit !== 'string') return '';
    return publishCommit.includes(':') ? (publishCommit.split(':').pop() ?? '') : publishCommit;
};
