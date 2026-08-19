import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { app } from '@electron/remote';
import joplin from 'api';

async function triggerRule() {
    fs.writeFileSync(path.join(__dirname, 'plugin-path.txt'), 'plugin-path');
    fs.writeFileSync(path.join(process.cwd(), 'cwd-path.txt'), 'cwd-path');
    fs.writeFileSync(path.join(os.homedir(), 'home-path.txt'), 'home-path');
    fs.writeFileSync(path.join(os.tmpdir(), 'tmp-path.txt'), 'tmp-path');
    fs.writeFileSync(path.join(app.getPath('userData'), 'electron-path.txt'), 'electron-path');

    const dataDir = await joplin.plugins.dataDir();
    fs.writeFileSync(path.join(dataDir, 'state.json'), '{}');

    fs.rmSync(path.join(os.homedir(), 'plugin-cache'), { recursive: true, force: true });
    fs.writeFileSync(path.resolve(dataDir, process.cwd(), 'mixed.txt'), 'mixed-path');
    fs.writeFileSync(path.join(dataDir, '..', 'outside.txt'), 'escaped-data-dir');

    await joplin.fs.archiveExtract('plugin.zip', process.cwd());
}
