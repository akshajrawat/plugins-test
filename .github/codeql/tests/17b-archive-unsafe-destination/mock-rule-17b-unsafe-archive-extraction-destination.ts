import * as joplin from 'api';
import * as electron from 'electron';
import * as os from 'os';

async function triggerRule() {
    await joplin.fs.archiveExtract('plugin.zip', '/etc/passwd');
    await joplin.fs.archiveExtract('plugin.zip', __dirname + '/overwrite');
    await joplin.fs.archiveExtract('plugin.zip', process.cwd());
    await joplin.fs.archiveExtract('plugin.zip', process.env as any);
    await joplin.fs.archiveExtract('plugin.zip', __filename);
    await joplin.fs.archiveExtract('plugin.zip', os.homedir());
    await joplin.fs.archiveExtract('plugin.zip', os.tmpdir());
    await joplin.fs.archiveExtract('plugin.zip', electron.app.getPath('userData'));

    const installDir = await joplin.plugins.installationDir();
    await joplin.fs.archiveExtract('plugin.zip', installDir);

    const dataDir = await joplin.plugins.dataDir();
    await joplin.fs.archiveExtract('plugin.zip', dataDir);
}
