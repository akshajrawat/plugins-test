import * as childProcess from 'child_process';
import * as joplin from 'api';

async function settingsSources() {
    const theme = await joplin.settings.globalValue('theme');
    childProcess.exec('apply-theme ' + theme);

    const preferences = await joplin.settings.globalValues(['theme', 'locale']);
    childProcess.spawn('apply-settings', preferences as string[]);
}

async function dataSources() {
    const note = await joplin.data.get(['notes', '1']);
    childProcess.execFile(note.title, []);
    childProcess.execFile('node', ['-e', note.body]);
    childProcess.spawn('cp', [note.title, '/tmp/backup'], { shell: true });

    const hidden = await joplin.data.userDataGet(['notes', '1'], 'command');
    childProcess.spawn(hidden as any, []);

    const selected = await joplin.workspace.selectedNote();
    childProcess.execSync(selected.title);
}

function workspaceSource() {
    joplin.workspace.onNoteChange((event: any) => {
        childProcess.execFile('note-changed', [event.itemId]);
    });
}

function messageSources(panel: string, editor: string, contentScriptId: string) {
    joplin.views.panels.onMessage(panel, (message: any) => {
        childProcess.spawnSync(message.command, message.args);
    });

    joplin.views.editors.onMessage(editor, (message: any) => {
        childProcess.spawn('editor-message', message.args);
    });

    joplin.contentScripts.onMessage(contentScriptId, (message: any) => {
        childProcess.exec(message.command);
    });
}

function editorSources(editor: string) {
    joplin.views.editors.onUpdate(editor, async event => {
        childProcess.spawn('update-editor', ['--body', event.newBody]);
    });

    joplin.views.editors.onActivationCheck(editor, async event => {
        childProcess.execFile('check-editor', [event.noteId]);
        return true;
    });

    joplin.views.editors.register('registered-editor', {
        onActivationCheck: async event => {
            childProcess.execFile('activate-editor', [event.noteId]);
            return true;
        },
        onSetup: async handle => {
            childProcess.spawn('setup-editor', [handle]);
        },
    });
}

async function dialogSource(dialog: string) {
    const result = await joplin.views.dialogs.open(dialog);
    const command = result.formData?.command;
    if (typeof command === 'string') childProcess.exec(command);
}

async function safeCases() {
    const sensitive = await joplin.settings.globalValue('api.token');
    childProcess.exec(sensitive);

    const mixed = await joplin.settings.globalValues(['theme', 'api.token']);
    childProcess.exec(mixed[1]);

    const selected = await joplin.workspace.selectedNote();
    childProcess.spawn('node', ['script.js'], {
        env: { NOTE_ID: selected?.id ?? '' },
    });

    const note = await joplin.data.get(['notes', '1']);
    console.info(note.title);

    const profileDir = await joplin.settings.globalValue('profileDir');
    childProcess.execFile('cp', ['-r', profileDir, '/tmp/profile-backup']);
    childProcess.execFile('mv', [profileDir, '/tmp/profile-old']);

    const unrelated = {
        onMessage: (_id: string, callback: (message: any)=> void) => callback({ command: 'echo safe' }),
    };
    unrelated.onMessage('view', message => {
        childProcess.exec(message.command);
    });
}
