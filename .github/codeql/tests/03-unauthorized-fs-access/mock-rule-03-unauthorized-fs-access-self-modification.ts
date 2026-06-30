import * as joplin from 'api';
import * as fs from 'fs';
import * as fsExtra from 'fs-extra';
import * as os from 'os';
import * as path from 'path';
import { app } from 'electron';

async function triggerRule() {
    // Positive: unsafe path-revealing sources

    const p1 = path.join(__dirname, 'modified.js');
    fs.writeFileSync(p1, 'data');

    const p2 = path.join(__filename, '../modified.js');
    fs.appendFileSync(p2, 'data');

    const p3 = path.join(process.cwd(), 'out.txt');
    fs.unlinkSync(p3);

    const p4 = path.join(app.getPath('home'), 'evil.txt');
    fs.rmSync(p4, { force: true });

    const p5 = path.join(os.homedir(), '.ssh', 'config');
    fsExtra.removeSync(p5);

    const p6 = path.join(__dirname, 'new-dir');
    fs.mkdirSync(p6);

    const p7 = path.join(process.cwd(), 'stream.txt');
    fs.createWriteStream(p7);

    const p8 = path.join(os.homedir(), 'copy.txt');
    fs.copyFileSync(p8, '/tmp/copy.txt');

    const p9 = path.join(os.homedir(), 'move.txt');
    fs.renameSync(p9, '/tmp/move.txt');

    // Positive: direct unsafe source to sink

    fs.writeFileSync(__dirname, 'data');
    fs.writeFileSync(__filename, 'data');
    fs.writeFileSync(process.cwd(), 'data');
    fs.writeFileSync(os.homedir(), 'data');
    fs.writeFileSync(app.getPath('home'), 'data');

    // Negative: safe Joplin plugin data dir

    const dataDir = await joplin.plugins.dataDir();
    const safePath = path.join(dataDir, 'cache.json');
    fs.writeFileSync(safePath, 'safe');

    // Negative: tmpdir is allowed by this rule

    const tmpPath = path.join(os.tmpdir(), 'cache.tmp');
    fs.writeFileSync(tmpPath, 'safe');

    // Negative: local hardcoded path has no suspicious source

    fs.writeFileSync('/tmp/static-file.txt', 'safe');

    // Check installationDir behavior.
    // This should NOT alert with your current rule because installationDir() is treated as safe.
    const installDir = await joplin.plugins.installationDir();
    const installPath = path.join(installDir, 'plugin.js');
    fs.writeFileSync(installPath, 'safe-by-current-rule');
}

triggerRule();