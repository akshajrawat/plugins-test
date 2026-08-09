import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as joplin from 'api';

async function triggerRule() {
    const entries = await joplin.fs.archiveExtract('safe.zip', await joplin.plugins.dataDir());
    fs.writeFileSync(entries[0].name, 'payload');

    entries.forEach((entry: any) => {
        childProcess.execFile(entry.entryName, []);
    });

    fs.writeFileSync(path.basename(entries[1].name), 'safe');
}
