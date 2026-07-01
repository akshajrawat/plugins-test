import * as childProcess from 'child_process';
import * as joplin from 'api';

async function triggerRule() {
    const copied = await joplin.clipboard.readText();
    eval(copied);
    childProcess.exec(copied);
}

export {};
