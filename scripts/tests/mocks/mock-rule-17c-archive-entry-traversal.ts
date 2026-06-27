import * as joplin from 'api';
import * as fsNative from 'fs';

async function triggerRule() {
    // Rule 17c : Archive Entry Traversal
    // Flow 1: archiveExtract entry name -> fs
    const r17cEntries = await joplin.fs.archiveExtract('safe.zip', await joplin.plugins.dataDir());
    fsNative.writeFileSync(r17cEntries[0].name, 'pwned');
}

export {};
