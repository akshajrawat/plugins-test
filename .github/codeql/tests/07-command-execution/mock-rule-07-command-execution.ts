import * as childProcess from 'child_process';
import * as joplin from 'api';

async function triggerRule(panel: string) {
    const theme = await joplin.settings.globalValue('theme');
    childProcess.exec('apply-theme ' + theme);

    const note = await joplin.data.get(['notes', '1']);
    childProcess.execFile(note.title, []);

    const hidden = await joplin.data.userDataGet(['notes', '1'], 'command');
    childProcess.spawn(hidden as any, []);

    const selected = await joplin.workspace.selectedNote();
    childProcess.execSync(selected.title);

    joplin.workspace.onNoteChange((event: any) => {
        childProcess.exec('note-changed ' + event.id);
    });

    joplin.views.panels.onMessage(panel, (message: any) => {
        childProcess.spawnSync(message.command, message.args);
    });
}

export {};
