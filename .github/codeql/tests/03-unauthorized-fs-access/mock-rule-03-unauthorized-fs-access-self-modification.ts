import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as electron from 'electron';
import * as joplin from 'api';

async function triggerRule() {
    fs.writeFileSync(__dirname, 'plugin-path');
    fs.writeFileSync(process.cwd(), 'cwd-path');
    fs.writeFileSync(os.homedir(), 'home-path');
    fs.writeFileSync(os.tmpdir(), 'tmp-path');
    fs.writeFileSync(electron.app.getPath('userData'), 'electron-path');

    const dataDir = await joplin.plugins.dataDir();
    fs.writeFileSync(path.join(dataDir, 'state.json'), '{}');

    fs.rmSync(path.join(os.homedir(), 'plugin-cache'), { recursive: true, force: true });
    fs.writeFileSync(path.resolve(dataDir, process.cwd(), 'mixed.txt'), 'mixed-path');
    fs.writeFileSync(path.join(dataDir, '..', 'outside.txt'), 'escaped-data-dir');

    await joplin.fs.archiveExtract('plugin.zip', process.cwd());
}
