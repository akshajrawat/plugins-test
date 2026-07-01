import * as joplin from 'api';

async function triggerRule(url: string) {
    const copied = await joplin.clipboard.readText();
    await joplin.clipboard.writeHtml('<b>' + copied + '</b>');

    const remote = await fetch(url);
    await joplin.clipboard.writeText(await remote.text());
}

export {};
