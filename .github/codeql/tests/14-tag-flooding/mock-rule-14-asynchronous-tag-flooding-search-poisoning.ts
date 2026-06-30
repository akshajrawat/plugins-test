// FROM : 
// 'spam' string literal / setInterval()
// 
// TO : 
// joplin.data.post

import * as joplin from 'api';

async function triggerRule() {
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 100);

}

export {};
