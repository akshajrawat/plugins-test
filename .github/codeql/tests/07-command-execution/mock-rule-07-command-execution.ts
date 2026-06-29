// FROM : 
// joplin.settings.globalValue('locale') / joplin.data.get() / joplin.workspace.selectedNote() / 'ls' / './script.js'
// 
// TO : 
// directCp.exec / directCp.execFile / directCp.spawn / directCp.execSync / directCp.execFileSync / directCp.spawnSync / directCp.fork

import * as joplin from 'api';
import * as directCp from 'child_process';

async function triggerRule() {
    const s1 = await joplin.settings.globalValue('locale');
    directCp.exec('echo ' + s1);
    directCp.execFile('echo', [s1]);
    directCp.spawn('echo', [s1]);
    directCp.execSync(s1);
    directCp.execFileSync(s1, ['-la']);
    directCp.spawnSync(s1, ['-la']);
    directCp.fork(s1);

    const s2 = (await joplin.data.get(['notes', '1'])).title;
    directCp.exec('echo ' + s2);
    directCp.execFile('echo', [s2]);
    directCp.spawn('echo', [s2]);
    directCp.execSync(s2);
    directCp.execFileSync(s2, ['-la']);
    directCp.spawnSync(s2, ['-la']);
    directCp.fork(s2);

    const s3 = (await joplin.workspace.selectedNote()).title;
    directCp.exec('echo ' + s3);
    directCp.execFile('echo', [s3]);
    directCp.spawn('echo', [s3]);
    directCp.execSync(s3);
    directCp.execFileSync(s3, ['-la']);
    directCp.spawnSync(s3, ['-la']);
    directCp.fork(s3);

    const s4 = 'ls';
    directCp.exec('echo ' + s4);
    directCp.execFile('echo', [s4]);
    directCp.spawn('echo', [s4]);
    directCp.execSync(s4);
    directCp.execFileSync(s4, ['-la']);
    directCp.spawnSync(s4, ['-la']);
    directCp.fork(s4);

    const s5 = './script.js';
    directCp.exec('echo ' + s5);
    directCp.execFile('echo', [s5]);
    directCp.spawn('echo', [s5]);
    directCp.execSync(s5);
    directCp.execFileSync(s5, ['-la']);
    directCp.spawnSync(s5, ['-la']);
    directCp.fork(s5);
}

export {};