import * as joplin from 'api';

function triggerRule() {
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        await joplin.data.put(['notes', event.id], null, { body: 'changed' });
    });

    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.delete(['notes', event.id]);
    });

    joplin.workspace.onNoteContentChange(async () => {
        await joplin.commands.execute('replaceSelection', 'updated');
    });
}

export {};
