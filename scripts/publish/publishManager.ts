import { join } from 'path';
import type { GithubContext } from '../code-scan/types';

const getRunUrl = (context: any) => 
    `https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;

export const parseIssuePayload = (body: string | null | undefined): any => {
    const jsonMatch = (body ?? '').match(/```json\s*([\s\S]*?)\s*```/);
    if (!jsonMatch) {
        return { ok: false, error: 'Could not find a JSON payload in the issue body.' };
    }
    try {
        const payload = JSON.parse(jsonMatch[1]);
        if (!payload.plugin_name || !payload.repository_url || !payload.commit_hash) {
            return { ok: false, error: 'Missing required fields in payload.' };
        }
        return { ok: true, payload };
    } catch {
        return { ok: false, error: 'Invalid JSON payload syntax.' };
    }
};

export const acknowledgePublishInitialization = async ({ github, context, core }: GithubContext) => {
    const body = `# Plugin Publish Initializing\nSetting up the environment to publish the approved plugin.\n\n**Workflow Run:** [View Logs](${getRunUrl(context)})`;
    const comment = await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body,
    });
    
    const validation = parseIssuePayload(context.payload.issue.body);
    if (!validation.ok) {
        core.setFailed(`Validation Error: ${validation.error}`);
        core.setOutput('should_proceed', 'false');
        return { should_proceed: false };
    }

    let repoName = validation.payload.repository_url;
    try {
        const repoUrl = new URL(validation.payload.repository_url);
        repoName = repoUrl.pathname.replace(/^\/|\/$/g, '').replace(/\.git$/, '');
    } catch (e) {
        // Ignore fallback
    }

    core.setOutput('plugin_name', validation.payload.plugin_name);
    core.setOutput('repository_url', repoName);
    core.setOutput('commit_hash', validation.payload.commit_hash);
    core.setOutput('comment_id', comment.data.id.toString());
    core.setOutput('should_proceed', 'true');
    return { should_proceed: true, comment_id: comment.data.id.toString() };
};

export const updatePublishPhase = async ({ github, context, core }: GithubContext, commentId: string | number, message: string) => {
    const body = `# Plugin Publish Status\n${message}\n\n**Workflow Run:** [View Logs](${getRunUrl(context)})`;
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: typeof commentId === 'number' ? commentId : parseInt(commentId as string, 10),
        body,
    });
};

export const finishPublish = async ({ github, context, core }: GithubContext, commentId: string | number) => {
    const validation = parseIssuePayload(context.payload.issue.body);
    const pluginName = validation.ok ? validation.payload.plugin_name : 'the plugin';
    const body = `# Plugin Published Successfully! 🎉\n\nThe plugin **${pluginName}** has been successfully published to the registry and its release has been updated.\n\n**Workflow Run:** [View Logs](${getRunUrl(context)})`;
    
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: typeof commentId === 'number' ? commentId : parseInt(commentId as string, 10),
        body,
    });

    await github.rest.issues.update({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        state: 'closed',
        state_reason: 'completed'
    });
};

export const handleWorkflowFailure = async ({ github, context, core }: GithubContext, commentId: string | number) => {
    const body = `# Plugin Publish Failed ❌\n\nThe publish workflow encountered an error. Please check the workflow logs for more details.\n\n**Workflow Run:** [View Logs](${getRunUrl(context)})`;
    if (commentId) {
        await github.rest.issues.updateComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            comment_id: typeof commentId === 'number' ? commentId : parseInt(commentId as string, 10),
            body,
        });
    } else {
        await github.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.issue.number,
            body,
        });
    }
};
