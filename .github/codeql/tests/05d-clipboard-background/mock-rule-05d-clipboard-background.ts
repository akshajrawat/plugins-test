import * as joplin from 'api';

function intervalAccess() {
    setInterval(() => {
        joplin.clipboard.readText();
        joplin.clipboard.write({ text: 'replacement' });
    }, 1000);

    function readHtmlInHelper() {
        joplin.clipboard.readHtml();
    }
    setInterval(() => readHtmlInHelper(), 1000);
}

function unboundedLoopAccess() {
    while (true) {
        joplin.clipboard.writeText('replacement');
    }
}

function boundedLoopAccess() {
    for (let index = 0; index < 2; index++) {
        joplin.clipboard.readImage();
    }
}

function recursiveTimeoutAccess() {
    function pollClipboard() {
        joplin.clipboard.readHtml();
        setTimeout(() => pollClipboard(), 1000);
    }

    pollClipboard();
}

function iterationAccess() {
    [1, 2].forEach(() => {
        joplin.clipboard.writeHtml('<strong>replacement</strong>');
    });

    [1, 2].map(() => {
        joplin.clipboard.writeImage('data:image/png;base64,replacement');
    });
}

function safeCases() {
    joplin.clipboard.readText();

    setTimeout(() => {
        joplin.clipboard.readHtml();
    }, 1000);

    setInterval(() => {
        const unused = () => {
            joplin.clipboard.writeText('not executed');
        };
        console.info(unused);
    }, 1000);
}
