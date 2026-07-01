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

    for (const tag of ['project', 'todo']) {
        joplin.data.post(['tags'], null, { title: tag });
    }

    ['note-1', 'note-2'].forEach((noteId) => {
        joplin.data.post(['tags', 'tag-1', 'notes'], null, { id: noteId });
    });

    ['resource-1', 'resource-2'].map((resourceId) => {
        joplin.data.post(['resources'], null, { id: resourceId });
    });
}

export {};
