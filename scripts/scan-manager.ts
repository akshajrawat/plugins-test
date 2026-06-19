import * as fs from 'fs';

const STATUS_TEMPLATE = (repoUrl: string, commitHash: string, runUrl: string, phases: Record<number, string> | null) => {
    let base = `# 🛡️Security Scan Report

**Target:** [${repoUrl}/commit/${commitHash}](${repoUrl}/commit/${commitHash})
**Workflow Run:** [View Logs](${runUrl})
`;
    if (phases) {
        base += `
# ⏳ Pipeline Status
* ${phases[1]} **Phase 1: Identity & Uniqueness Check**
* ${phases[2]} **Phase 2: Environment Provisioning**
* ${phases[3]} **Phase 3: CodeQL Database Compilation**
* ${phases[4]} **Phase 4: SAST Taint Analysis**
* ${phases[5]} **Phase 5: Final Report Generation**
`;
    }
    return base;
};

function getPhases(currentPhase: number): Record<number, string> {
    const phases: Record<number, string> = {};
    for (let i = 1; i <= 5; i++) {
        if (i < currentPhase) phases[i] = '✅';
        else if (i === currentPhase) phases[i] = '🔄';
        else phases[i] = '⚪';
    }
    if (currentPhase > 5) {
        for (let i = 1; i <= 5; i++) phases[i] = '✅';
    }
    return phases;
}

function normalizeUrl(url: string): string {
    return url.replace(/\/$/, '').toLowerCase();
}

interface GithubContext {
    github: any;
    context: any;
    core: any;
}

export async function initialize({ github, context, core }: GithubContext) {
    const issueBody = context.payload.issue.body;
    const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;

    const initialCommentId = process.env.INITIAL_COMMENT_ID;
    const failWithComment = async (msg: string) => {
        if (initialCommentId) {
            await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: parseInt(initialCommentId),
                body: `❌ **Security Scan Failed**\n\n${msg}\n\n**Workflow Run:** [View Logs](${runUrl})`
            });
        }
        core.setOutput('handled_failure', 'true');
        core.setFailed(msg);
        return { should_proceed: false };
    };

    const jsonMatch = issueBody.match(/```json\s*([\s\S]*?)\s*```/);
    if (!jsonMatch) {
        return await failWithComment("Could not find JSON payload in the issue body. Please ensure you included a \`\`\`json block.");
    }

    let payload: any;
    try {
        payload = JSON.parse(jsonMatch[1]);
    } catch (e) {
        return await failWithComment("Invalid JSON payload. Please check for syntax errors.");
    }

    const { plugin_name, repository_url, commit_hash } = payload;

    if (!plugin_name || !repository_url || !commit_hash) {
        return await failWithComment("Missing required fields in payload. Ensure \`plugin_name\`, \`repository_url\`, and \`commit_hash\` are provided.");
    }

    const phases = getPhases(1);
    const commentBody = STATUS_TEMPLATE(repository_url, commit_hash, runUrl, phases);

    let comment;
    if (initialCommentId) {
        comment = await github.rest.issues.updateComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            comment_id: parseInt(initialCommentId),
            body: commentBody
        });
    } else {
        comment = await github.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.issue.number,
            body: commentBody
        });
    }

    const manifestsPath = './plugins-test/manifests.json';
    if (fs.existsSync(manifestsPath)) {
        const manifests = JSON.parse(fs.readFileSync(manifestsPath, 'utf8'));

        let existingPlugin = manifests[plugin_name];
        if (!existingPlugin) {
            for (const key in manifests) {
                if (manifests[key].name === plugin_name) {
                    existingPlugin = manifests[key];
                    break;
                }
            }
        }

        if (existingPlugin) {
            const registeredUrl = existingPlugin.repository_url;
            if (registeredUrl && normalizeUrl(registeredUrl) !== normalizeUrl(repository_url)) {
                const rejectMsg = `🚨 **Security Reject:** Plugin \`${plugin_name}\` already exists, but the repository URL does not match the registered owner.\n\nExpected: ${registeredUrl}\nProvided: ${repository_url}`;
                await github.rest.issues.updateComment({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    comment_id: comment.data.id,
                    body: commentBody + `\n\n${rejectMsg}`
                });
                await github.rest.issues.update({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    issue_number: context.issue.number,
                    state: 'closed'
                });
                core.setOutput('handled_failure', 'true');
                core.setFailed("Ownership mismatch. Issue closed.");
                return { should_proceed: false };
            }
        }
    }

    const urlParts = normalizeUrl(repository_url).split('/');
    let repoName = urlParts.slice(-2).join('/');
    repoName = repoName.replace(/\.git$/, '');

    core.setOutput('repository_url', repository_url);
    core.setOutput('commit_hash', commit_hash);
    core.setOutput('repo_name', repoName);
    core.setOutput('comment_id', comment.data.id.toString());
    core.setOutput('should_proceed', 'true');

    return {
        repository_url,
        commit_hash,
        repo_name: repoName,
        comment_id: comment.data.id,
        should_proceed: true
    };
}

export async function updatePhase({ github, context }: Partial<GithubContext>, comment_id: string, phase: number) {
    const comment = await github.rest.issues.getComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: parseInt(comment_id)
    });

    let body = comment.data.body;
    const repoUrlMatch = body.match(/\*\*Target:\*\* \[([^\]]+)\/commit\//);
    const repoUrl = repoUrlMatch ? repoUrlMatch[1] : '';
    const commitHashMatch = body.match(/\*\*Target:\*\* \[.*?\/commit\/([^\]]+)\]/);
    const commitHash = commitHashMatch ? commitHashMatch[1] : '';
    const runUrlMatch = body.match(/\*\*Workflow Run:\*\* \[.*?\]\(([^)]+)\)/);
    const runUrl = runUrlMatch ? runUrlMatch[1] : '';

    const phases = getPhases(phase);
    const newHeader = STATUS_TEMPLATE(repoUrl, commitHash, runUrl, phases);

    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: parseInt(comment_id),
        body: newHeader
    });
}

export async function generateFinalReport({ github, context }: Partial<GithubContext>, comment_id: string, sarifPath: string, repoUrl: string, commitHash: string) {
    const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
    let body = STATUS_TEMPLATE(repoUrl, commitHash, runUrl, null) + `\n\n---\n\n# Findings\n\n`;

    if (fs.existsSync(sarifPath)) {
        const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
        let results: any[] = [];
        sarif.runs.forEach((run: any) => {
            if (run.results) {
                results = results.concat(run.results);
            }
        });

        if (results && results.length > 0) {
            results.forEach(result => {
                const ruleId = result.ruleId;
                let rawMessage = result.message.text || '';
                const message = Array.from(new Set(rawMessage.split('\n').map((s: string) => s.trim()))).filter(Boolean).join(' ');
                const location = result.locations[0].physicalLocation;
                const file = location.artifactLocation.uri;
                const line = location.region.startLine;

                let rule: any = null;
                sarif.runs.forEach((run: any) => {
                    if (run.tool.driver.rules) {
                        const found = run.tool.driver.rules.find((r: any) => r.id === ruleId);
                        if (found) rule = found;
                    }
                });

                const severityLevel = rule?.defaultConfiguration?.level || 'warning';
                const icon = severityLevel === 'error' ? '🔴 CRITICAL' : (severityLevel === 'warning' ? '🟡 WARNING' : '🔵 INFO');
                const title = rule?.shortDescription?.text || rule?.name || ruleId;

                body += `### ${icon}: ${title}\n`;
                body += `* **Rule Violated:** \`${ruleId}\`\n`;
                body += `* **Flagged For:** ${message}\n`;
                body += `* **Location:** [\`${file}#L${line}\`](${repoUrl}/blob/${commitHash}/${file}#L${line})\n\n`;
            });
        } else {
            body += `✅ **No vulnerabilities detected by CodeQL.**\n`;
        }
    } else {
        body += `❌ **Failed to generate SARIF report or CodeQL analysis failed.**\n`;
    }

    await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: parseInt(comment_id),
        body: body
    });
}
