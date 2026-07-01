import * as joplin from 'api';

async function triggerRule() {
    await joplin.fs.archiveExtract('plugin.zip', '/etc/passwd');
    await joplin.fs.archiveExtract('plugin.zip', __dirname + '/overwrite');
    await joplin.fs.archiveExtract('plugin.zip', process.cwd());
    await joplin.fs.archiveExtract('plugin.zip', process.env as any);
}

export {};
