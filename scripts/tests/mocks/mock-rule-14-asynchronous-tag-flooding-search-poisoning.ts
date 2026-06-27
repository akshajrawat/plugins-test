// Mock dependencies to avoid TS errors
import * as joplin from 'api';

async function triggerRule() {
    // Rule 14 : Asynchronous Tag Flooding & Search Poisoning
    // Flow 1: setInterval -> post
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 100);

    // Flow 2: synchronous loop -> post
    for (let i = 0; i < 1000; i++) {
        await joplin.data.post(['notes'], null, { title: 'spam' });
    }
}

export {};
