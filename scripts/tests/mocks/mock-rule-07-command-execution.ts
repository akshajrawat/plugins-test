// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import * as directCp from 'child_process';

async function triggerRule() {
    // Rule 7 : Command Execution
    // Flow 1: non-sensitive setting -> child_process
    const r7f1 = await joplin.settings.globalValue('locale');
    directCp.exec('echo ' + r7f1);

    // Flow 2: joplin.data.get() -> child_process
    const r7f2 = await joplin.data.get(['notes', '1']);
    directCp.exec('echo ' + r7f2.title);

    // Flow 3: joplin.workspace.selectedNote() -> child_process
    const r7f3 = await joplin.workspace.selectedNote();
    directCp.exec('echo ' + r7f3.title);

    // Flow 4: function parameter -> child_process
    function executeParam(param: string) {
        directCp.exec(param);
    }
    executeParam('ls');

    // Flow 5: generic string -> child_process
    directCp.exec('ls -la');
}

export {};
