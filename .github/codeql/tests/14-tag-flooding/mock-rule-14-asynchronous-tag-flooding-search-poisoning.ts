import * as fs from 'fs';
import { appendFile as appendFilePromise } from 'node:fs/promises';
import joplin from 'api';

function createFolder() {
    joplin.data.post(['folders'], null, { title: 'spam' });
}

function triggerRule() {
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 1000);

    setInterval(() => {
        createFolder();
    }, 1000);

    while (true) {
        fs.writeFileSync('/tmp/flood.txt', 'x');
    }
}

function triggerExactRoutes() {
    for (;;) {
        joplin.data.post(['notes'], null, { title: 'spam' });
        joplin.data.post(['resources'], null, { title: 'spam' });
        joplin.data.post(['tags', 'tag-1', 'notes'], null, { id: 'note-1' });
    }
}

function triggerRecursiveTimeout() {
    joplin.data.post(['notes'], null, { title: 'recurring' });
    setTimeout(triggerRecursiveTimeout, 1000);
}

async function triggerFilesystemVariants() {
    const extraFs = joplin.require('fs-extra');

    while (true) {
        await appendFilePromise('/tmp/promises-flood.txt', 'x');
        await extraFs.outputFile('/tmp/joplin-fs-extra-flood.txt', 'x');
    }
}

function triggerLargeWrite() {
    for (let i = 0; i < 2; i++) {
        fs.writeFileSync('/tmp/large.txt', Buffer.alloc(20000));
    }
}

function safeCases() {
    for (const tag of ['project', 'todo']) {
        joplin.data.post(['tags'], null, { title: tag });
    }

    ['note-1', 'note-2'].forEach((noteId) => {
        joplin.data.post(['tags', 'tag-1', 'notes'], null, { id: noteId });
    });

    const interval = setInterval(() => {
        joplin.data.post(['resources'], null, { title: 'temporary' });
    }, 1000);
    clearInterval(interval);

    while (true) {
        joplin.data.put(['tags', 'tag-1'], null, { title: 'updated' });
    }
}
