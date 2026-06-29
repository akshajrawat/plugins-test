// FROM : 
// loop / 'folders' / 'notes'
// 
// TO : 
// joplin.data.delete / joplin.data.put

import * as joplin from 'api';

async function triggerRule() {
    await joplin.data.delete(['folders', '123']);
    
    for (let i = 0; i < 100; i++) {
        await joplin.data.delete(['notes', i.toString()]);
    }
    
    for (let i = 0; i < 100; i++) {
        await joplin.data.put(['notes', i.toString()], null, { deleted_time: Date.now() });
    }
}

export {};
