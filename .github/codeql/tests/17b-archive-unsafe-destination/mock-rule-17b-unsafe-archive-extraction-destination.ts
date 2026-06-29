// FROM : 
// 'safe.zip' / '/etc/passwd'
// 
// TO : 
// joplin.fs.archiveExtract

import * as joplin from 'api';

async function triggerRule() {
    await joplin.fs.archiveExtract('safe.zip', '/etc/passwd');
}

export {};
