import * as childProcess from 'child_process';
import joplin from 'api';
import { ModelType } from 'api/types';

async function triggerRule() {
    const note = await joplin.data.get(['notes', 'source-note']);
    await joplin.data.userDataSet(ModelType.Note, 'target-note', 'shadow', note.body);

    const folder = await joplin.data.get(['folders', 'source-folder']);
    await joplin.data.userDataSet(ModelType.Note, 'target-note', 'folder-copy', folder.title);

    const resource = await joplin.data.get(['resources', 'source-resource']);
    await joplin.data.userDataSet(ModelType.Note, 'target-note', 'resource-copy', resource.id);

    const masterKey = await joplin.data.get(['master_keys', 'source-key']);
    await joplin.data.userDataSet(ModelType.Note, 'target-note', 'key-copy', masterKey.content);

    const payload = await joplin.data.userDataGet<string>(ModelType.Note, 'target-note', 'shadow');
    eval(payload);
    Function(payload)();
    new Function(payload)();
    setTimeout(payload, 100);
    setInterval(payload, 100);
    childProcess.exec(payload);
}

async function safeCases() {
    const noteId = 'same-note';
    const note = await joplin.data.get(['notes', noteId]);
    await joplin.data.userDataSet(ModelType.Note, noteId, 'cached-body', note.body);

    const folderId = 'same-folder';
    const folder = await joplin.data.get(['folders', folderId]);
    await joplin.data.userDataSet(ModelType.Folder, folderId, 'cached-title', folder.title);

    const payload = await joplin.data.userDataGet<string>(ModelType.Note, noteId, 'cached-body');
    console.info(payload);

    eval('const localValue = 1;');
}
