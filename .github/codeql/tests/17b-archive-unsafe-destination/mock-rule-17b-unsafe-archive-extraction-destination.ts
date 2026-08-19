import { app } from '@electron/remote';
import * as os from 'node:os';
import * as path from 'node:path';
import joplin from 'api';

async function triggerRule(panel: string) {
    await joplin.fs.archiveExtract('plugin.zip', '/etc/extract-output');
    await joplin.fs.archiveExtract('plugin.zip', __dirname + '/overwrite');
    await joplin.fs.archiveExtract('plugin.zip', process.cwd());
    await joplin.fs.archiveExtract('plugin.zip', process.env.EXTRACT_DIR as string);
    await joplin.fs.archiveExtract('plugin.zip', process.argv[2]);
    await joplin.fs.archiveExtract('plugin.zip', path.dirname(__filename));
    await joplin.fs.archiveExtract('plugin.zip', os.homedir());
    await joplin.fs.archiveExtract('plugin.zip', os.tmpdir());
    await joplin.fs.archiveExtract('plugin.zip', app.getPath('userData'));
    await joplin.fs.archiveExtract('plugin.zip', 'relative-output');
    await joplin.fs.archiveExtract('plugin.zip', 'C:/Windows/output');
    await joplin.fs.archiveExtract('plugin.zip', 'C:\\Windows\\output');
    await joplin.fs.archiveExtract('plugin.zip', '\\\\server\\share\\output');

    const installDir = await joplin.plugins.installationDir();
    await joplin.fs.archiveExtract('plugin.zip', installDir);

    const configuredPath = await joplin.settings.value('extractPath');
    await joplin.fs.archiveExtract('plugin.zip', configuredPath as string);

    const dataDir = await joplin.plugins.dataDir();
    await joplin.fs.archiveExtract('plugin.zip', path.join(dataDir, '..', 'outside'));
    await joplin.fs.archiveExtract('plugin.zip', path.dirname(dataDir));

    joplin.views.panels.onMessage(panel, async (message: any) => {
        await joplin.fs.archiveExtract('plugin.zip', message.destination);
    });
}

async function safeCases() {
    const dataDir = await joplin.plugins.dataDir();
    await joplin.fs.archiveExtract('plugin.zip', dataDir);
    await joplin.fs.archiveExtract('plugin.zip', path.join(dataDir, 'archives', 'current'));

    const app = {
        getPath: () => dataDir,
    };
    await joplin.fs.archiveExtract('plugin.zip', app.getPath());
}
