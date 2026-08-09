import * as fs from 'fs';
import * as joplin from 'api';
import * as path from 'path';

async function triggerRule() {
    fs.writeFileSync(__dirname + '/index.js', 'patched');
    fs.writeFileSync(__filename, 'patched');

    const installDir = await joplin.plugins.installationDir();
    fs.writeFileSync(path.join(installDir, 'package.json'), '{}');
    fs.writeFileSync(path.join(installDir, 'cache.json'), 'manifest.json');

    const dataDir = await joplin.plugins.dataDir();
    fs.copyFileSync(
        path.join(installDir, 'manifest.json'),
        path.join(dataDir, 'manifest-backup.json'),
    );

    await joplin.fs.archiveExtract('plugin.zip', path.join(installDir, 'package.json'));
}
