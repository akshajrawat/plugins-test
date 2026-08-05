import type { GithubActionContext, GithubClient, GithubContext } from '../types/types';

export const runUrlFor = (context: GithubActionContext) => {
    const serverUrl = context.serverUrl ?? 'https://github.com';
    return `${serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
};

export const commentIdNumber = (commentId: string | number) => {
    const id = typeof commentId === 'number' ? commentId : Number.parseInt(commentId, 10);
    if (!Number.isInteger(id)) throw new Error(`Invalid issue comment id: ${commentId}`);
    return id;
};

export const updateComment = async (github: GithubClient, context: GithubActionContext, commentId: string | number, body: string) => {
    const id = commentIdNumber(commentId);
    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: id,
        body,
    });
};

export const createComment = async (github: GithubClient, context: GithubActionContext, body: string) => {
    return await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body,
    });
};

export const failWithIssueComment = async (
    { github, context, core }: GithubContext,
    commentId: string | number | undefined,
    heading: string,
    message: string,
) => {
    const runUrl = runUrlFor(context);
    const body = `# ${heading}\n${message}\n**Workflow Run:** [View Logs](${runUrl})`;

    if (commentId) {
        await updateComment(github, context, commentId, body);
    } else {
        await createComment(github, context, body);
    }

    core.setOutput('handled_failure', 'true');
    core.setFailed(message);

    return { should_proceed: false };
};
