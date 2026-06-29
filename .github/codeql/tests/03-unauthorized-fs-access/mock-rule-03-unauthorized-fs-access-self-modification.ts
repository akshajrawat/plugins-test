import * as joplin from 'api';
import * as electron from 'electron';
import * as fsNative from 'fs';
import * as fsExtraNative from 'fs-extra';
import * as os from 'os';
import * as path from 'path';

const app = electron.app;

// FROM : 
// __dirname / __filename / process.cwd() / app.getPath('userData') / os.homedir() / 
// path.resolve() / path.join() / fsNative / fsExtraNative / joplin.require('fs') / 
// joplin.require('fs-extra') / require('fs')
// 
// TO : 
// fsNative.writeFileSync / fsExtraNative.writeFileSync
async function triggerRule() {
    const s1 = __dirname + '/test';
    fsNative.writeFileSync(s1, 'payload');
    fsExtraNative.writeFileSync(s1, 'payload');

    const s2 = __filename + '/test';
    fsNative.writeFileSync(s2, 'payload');
    fsExtraNative.writeFileSync(s2, 'payload');

    const s3 = process.cwd() + '/test';
    fsNative.writeFileSync(s3, 'payload');
    fsExtraNative.writeFileSync(s3, 'payload');

    const s4 = app.getPath('userData') + '/test';
    fsNative.writeFileSync(s4, 'payload');
    fsExtraNative.writeFileSync(s4, 'payload');

    const s5 = os.homedir() + '/test';
    fsNative.writeFileSync(s5, 'payload');
    fsExtraNative.writeFileSync(s5, 'payload');

    const s6 = path.resolve('..', 'test');
    fsNative.writeFileSync(s6, 'payload');
    fsExtraNative.writeFileSync(s6, 'payload');

    const s7 = path.join('/tmp', 'test');
    fsNative.writeFileSync(s7, 'payload');
    fsExtraNative.writeFileSync(s7, 'payload');

    const s8 = fsNative as any;
    fsNative.writeFileSync(s8, 'payload');
    fsExtraNative.writeFileSync(s8, 'payload');

    const s9 = fsExtraNative as any;
    fsNative.writeFileSync(s9, 'payload');
    fsExtraNative.writeFileSync(s9, 'payload');

    const s10 = await (joplin as any).require('fs');
    fsNative.writeFileSync(s10, 'payload');
    fsExtraNative.writeFileSync(s10, 'payload');

    const s11 = await (joplin as any).require('fs-extra');
    fsNative.writeFileSync(s11, 'payload');
    fsExtraNative.writeFileSync(s11, 'payload');

    const s12 = require('fs');
    fsNative.writeFileSync(s12, 'payload');
    fsExtraNative.writeFileSync(s12, 'payload');
}

export { };