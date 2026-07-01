import * as fs from 'fs';
import * as joplin from 'api';

function triggerRule() {
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 1000);

    while (true) {
        fs.writeFileSync('/tmp/flood.txt', 'x');
    }

    for (let i = 0; i < 2; i++) {
        fs.writeFileSync('/tmp/large.txt', Buffer.alloc(20000));
    }
}

export {};
