// FROM : 
// 'folders'
// 
// TO : 
// joplin.data.delete

import * as joplin from 'api';

async function triggerRule() {
    await joplin.data.delete(['folders', '123']);

}

export {};
