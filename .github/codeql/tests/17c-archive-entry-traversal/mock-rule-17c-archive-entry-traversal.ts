// FROM : 
// joplin.fs.archiveExtract() / s1[0].name
// 
// TO : 
// fsNative.writeFileSync

import * as joplin from 'api';
import * as fsNative from 'fs';

async function triggerRule() {
    const s1 = await joplin.fs.archiveExtract('safe.zip', await joplin.plugins.dataDir());
    fsNative.writeFileSync(s1[0].name, 'pwned');
}

export {};
