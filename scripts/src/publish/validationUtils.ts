import type { SubmissionPayload } from '../types/types';
import type { PublishPayload, PublishSummary } from '../types/publishTypes';
import { getRegistryPath, readJsonFile } from '../utils/utils';
import { parseGithubRepository, normalizeRepositoryUrl, parseIssuePayload } from '../utils/payload';

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
        const normalizedRegisteredUrl = normalizeRepositoryUrl(registeredUrl);
        const normalizedPayloadUrl = normalizeRepositoryUrl(payload.repository_url);

        if (normalizedRegisteredUrl !== normalizedPayloadUrl) {
            return `Security reject: plugin ${payload.plugin_name} already exists, but the repository URL does not match the registered owner.\nExpected: ${registeredUrl}\nProvided: ${payload.repository_url}`;
        }
    }

    return '';
};

export const toPublishPayload = async (payload: SubmissionPayload): Promise<PublishPayload> => {
    const repository = parseGithubRepository(payload.repository_url);
    if (!repository) throw new Error(`Invalid repository URL: ${payload.repository_url}`);

    return {
        ...payload,
        repository_url: repository.canonicalUrl,
        repo_name: repository.repoName,
    };
};

export const parsePayloadFromContext = async (context: any): Promise<PublishPayload | null> => {
    const validation = parseIssuePayload(context.payload.issue.body);
    if (validation.ok === false) return null;
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
