// FROM : 
// joplin.data.get(['notes', '1']) / joplin.data.get(['master_keys', '1'])
// 
// TO : 
// joplin.data.userDataSet

import * as joplin from 'api';

async function triggerRule() {
    const s1 = await joplin.data.get(['notes', '1']);
    await joplin.data.userDataSet(s1.body);

    const s2 = await joplin.data.get(['master_keys', '1']);
    await joplin.data.userDataSet(s2.content);
}

export {};
