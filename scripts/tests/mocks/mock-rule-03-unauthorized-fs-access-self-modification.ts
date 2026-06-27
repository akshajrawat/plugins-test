// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import * as electron from 'electron';
import * as fsNative from 'fs';
import * as os from 'os';
import * as path from 'path';

const app = electron.app;

async function triggerRule() {
    // Rule 3 : Unauthorized FS Access / Self-Modification
    // Flow 1: __dirname / __filename -> fs path sink
    fsNative.writeFileSync(__dirname + '/test', 'payload');

    // Flow 2: process.cwd() -> fs path sink
    fsNative.writeFileSync(process.cwd() + '/test', 'payload');

    // Flow 3: app.getPath() -> fs path sink
    fsNative.writeFileSync(app.getPath('userData') + '/test', 'payload');

    // Flow 4: os.homedir() -> fs path sink
    fsNative.writeFileSync(os.homedir() + '/test', 'payload');

    // Flow 5: path.resolve() / path.join() -> fs path sink
    fsNative.writeFileSync(path.resolve('..', 'test'), 'payload');

    // Flow 6: joplin.plugins.dataDir -> filesystem path sink (safe flow test case)
    const dataDir = await joplin.plugins.dataDir();
    fsNative.writeFileSync(path.join(dataDir, 'test'), 'payload');

    // Flow 7: require("fs") module reference -> fs path sink
    fsNative.writeFileSync(fsNative as any, 'payload');
}

export {};
