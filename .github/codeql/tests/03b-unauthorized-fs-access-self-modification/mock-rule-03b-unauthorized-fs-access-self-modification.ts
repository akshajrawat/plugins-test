import * as fs from 'fs';
import * as joplin from 'api';

async function triggerRule() {
    fs.writeFileSync(__dirname + '/index.js', 'patched');
    fs.unlinkSync(__filename + '/manifest.json');

    const installDir = await joplin.plugins.installationDir();
    fs.writeFileSync(installDir + '/package.json', '{}');
}

export {};
