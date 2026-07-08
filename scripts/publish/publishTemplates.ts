import type { PublishPayload } from './types';
import { escapeMarkdownText, escapeMarkdownUrl } from './markdownUtils';

const phaseCount = 6;

export const statusLabel = async (phase: number, currentPhase: number) => {
    if (phase < currentPhase) return '✅';
    if (phase === currentPhase) return '⏳';
    return '⚪';
};

export const getPhases = async (currentPhase: number) => {
    const phases: Record<number, string> = {};

    for (let phase = 1; phase <= phaseCount; phase++) {
        phases[phase] = await statusLabel(phase, currentPhase);
    }

    if (currentPhase > phaseCount) {
        for (let phase = 1; phase <= phaseCount; phase++) {
            phases[phase] = '✅';
        }
    }

    return phases;
};

export const statusTemplate = async (
    payload: PublishPayload,
    runUrl: string,
    currentPhase: number,
    details?: string,
) => {
    const phases = await getPhases(currentPhase);
    const targetText = await escapeMarkdownText(`${payload.repository_url}/tree/${payload.commit_hash}`);
    const targetUrl = await escapeMarkdownUrl(`${payload.repository_url}/tree/${payload.commit_hash}`);
    const workflowRunUrl = await escapeMarkdownUrl(runUrl);
    const escapedDetails = details ? await escapeMarkdownText(details) : '';
    const detailBlock = details ? `\n\n${escapedDetails}` : '';
    const pluginNameText = await escapeMarkdownText(payload.plugin_name);

    return `# Plugin Publish Status
**Plugin:** ${pluginNameText}
**Target:** [${targetText}](${targetUrl})
**Workflow Run:** [View Logs](${workflowRunUrl})${detailBlock}

# Pipeline Status
* ${phases[1]} **Phase 1: Validate approved submission**
* ${phases[2]} **Phase 2: Build plugin artifact**
* ${phases[3]} **Phase 3: Download compiled artifact**
* ${phases[4]} **Phase 4: Publish registry files**
* ${phases[5]} **Phase 5: Update GitHub release and stats**
* ${phases[6]} **Phase 6: Commit registry update**`;
};

export const failureTemplate = async (heading: string, message: string, runUrl: string) => {
    const escapedMessage = await escapeMarkdownText(message);
    const workflowRunUrl = await escapeMarkdownUrl(runUrl);
    return `# ${heading}\n\n${escapedMessage}\n\n**Workflow Run:** [View Logs](${workflowRunUrl})`;
};
