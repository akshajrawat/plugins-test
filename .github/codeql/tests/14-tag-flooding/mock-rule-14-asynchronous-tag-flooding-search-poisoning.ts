// FROM : 
// 'spam' string literal / setInterval() / loop
// 
// TO : 
// joplin.data.post

import * as joplin from 'api';

async function triggerRule() {
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 100);

    for (let i = 0; i < 1000; i++) {
        await joplin.data.post(['notes'], null, { title: 'spam' });
    }
}

export {};
