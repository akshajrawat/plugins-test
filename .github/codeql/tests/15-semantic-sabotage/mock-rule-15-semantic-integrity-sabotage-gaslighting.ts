import * as joplin from 'api';

async function updateNote(noteId: string) {
    await joplin.data.put(['notes', noteId], null, { body: 'changed' });
}

function triggerRule() {
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        await updateNote(event.value[0]);
    });

    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.delete(['notes', event.id]);
    });

    joplin.workspace.onNoteContentChange(async () => {
        await joplin.commands.execute('replaceSelection', 'updated');
    });

    joplin.workspace.onNoteAlarmTrigger(async () => {
        await joplin.commands.execute('insertText', 'alarm text');
    });
}

async function mutationOutsideWorkspaceHook(noteId: string) {
    await joplin.data.put(['notes', noteId], null, { body: 'user initiated' });
}

function safeCases() {
    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.put(['folders', event.id], null, { title: 'not a note' });
        await joplin.data.delete(['notes', event.id, 'unsupported-sub-route']);
        await joplin.commands.execute('focus');

        async function unusedMutation() {
            await joplin.data.put(['notes', event.id], null, { body: 'never executed' });
        }
    });
}
