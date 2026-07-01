import * as joplin from 'api';

function triggerRule() {
    joplin.data.delete(['folders', 'archive']);

    while (true) {
        joplin.data.delete(['notes', 'loop-note']);
    }

    ['n1', 'n2'].forEach((id) => {
        joplin.data.put(['notes', id], null, { deleted_time: Date.now() });
    });

    setInterval(() => {
        joplin.data.put(['notes', 'blank'], null, { body: '' });
    }, 1000);
}

export {};
