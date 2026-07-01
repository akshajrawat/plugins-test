import * as joplin from 'api';

function triggerRule() {
    setInterval(() => {
        joplin.clipboard.readText();
    }, 1000);

    while (true) {
        joplin.clipboard.writeText('replacement');
    }
}

export {};
