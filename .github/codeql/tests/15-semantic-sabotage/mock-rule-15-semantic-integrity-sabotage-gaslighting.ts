import joplin from 'api';

async function updateNote(noteId: string) {
    await joplin.data.put(['notes', noteId], null, { body: 'changed' });
}

function triggerRule() {
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        await updateNote(event.value[0]);
    });

    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.delete(['notes', event.id]);
        await joplin.data.put(['notes', event.id], null, { deleted_time: Date.now() });
        await joplin.data.put(['notes', event.id], null, { is_conflict: true });
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

async function updateGeneratedSummary(noteId: string, body: string) {
    await joplin.data.put(['notes', noteId], null, { body });
}

function safeCases() {
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        const generatedSummary = `Summary for ${event.value[0]}`;
        await updateGeneratedSummary(event.value[0], generatedSummary);
    });

    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.put(['folders', 'unrelated-folder'], null, { title: 'not a note' });
        await joplin.data.delete(['tags', 'tag-id', 'notes', event.id]);
        await joplin.data.put(['notes', event.id], null, { deleted_time: 0 });
        await joplin.data.put(['notes', event.id], null, { is_conflict: false });
        await joplin.commands.execute('focusElement', 'noteBody');

        async function unusedMutation() {
            await joplin.data.put(['notes', event.id], null, { body: 'never executed' });
        }
    });
}
