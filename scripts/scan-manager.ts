import * as fs from 'fs';

const STATUS_TEMPLATE = (repoUrl: string, commitHash: string, runUrl: string, phases: Record<number, string>) => `
# 🛡️Security Scan Report

**Target:** [${repoUrl}/tree/${commitHash}](${repoUrl}/tree/${commitHash})
**Workflow Run:** [View Logs](${runUrl})

# ⏳ Pipeline Status
* ${phases[1]} **Phase 1: Identity & Uniqueness Check** — *Validating ownership...*
* ${phases[2]} **Phase 2: Environment Provisioning** — *Setting up workspace...*
* ${phases[3]} **Phase 3: CodeQL Database Compilation** — *Building database...*
* ${phases[4]} **Phase 4: SAST Taint Analysis** — *Running queries...*
* ${phases[5]} **Phase 5: Final Report Generation** — *Formatting results...*
`;

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

    const jsonMatch = issueBody.match(/```json\s*([\s\S]*?)\s*```/);
    if (!jsonMatch) {
        core.setFailed("Could not find JSON payload in the issue body.");
        return { should_proceed: false };
    }

    let payload: any;
    try {
        payload = JSON.parse(jsonMatch[1]);
    } catch (e) {
        core.setFailed("Invalid JSON payload.");
        return { should_proceed: false };
    }

    const { plugin_name, repository_url, commit_hash } = payload;

    if (!plugin_name || !repository_url || !commit_hash) {
        core.setFailed("Missing required fields in payload.");
        return { should_proceed: false };
    }

    const phases = getPhases(1);
    const commentBody = STATUS_TEMPLATE(repository_url, commit_hash, runUrl, phases);

    const comment = await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: commentBody
    });

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
    const repoUrlMatch = body.match(/\*\*Target:\*\* \[(.*?)\/tree\//);
    const repoUrl = repoUrlMatch ? repoUrlMatch[1] : '';
    const commitHashMatch = body.match(/\/tree\/([^)]+)\)/);
    const commitHash = commitHashMatch ? commitHashMatch[1] : '';
    const runUrlMatch = body.match(/\*\*Workflow Run:\*\* \[(.*?)\]/);
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
    const phases = getPhases(6);
    let body = STATUS_TEMPLATE(repoUrl, commitHash, runUrl, phases) + `\n\n---\n\n# Findings\n\n`;

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
                const message = result.message.text;
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
