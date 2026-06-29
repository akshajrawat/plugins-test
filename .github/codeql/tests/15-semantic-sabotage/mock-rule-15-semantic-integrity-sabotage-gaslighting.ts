// FROM : 
// joplin.workspace.onNoteSelectionChange() / joplin.workspace.onNoteChange()
// 
// TO : 
// joplin.data.put / joplin.data.delete

import * as joplin from 'api';

async function triggerRule() {
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        await joplin.data.put(['notes', event], null, { body: 'gaslight' });
    });

    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.delete(['notes', event]);
    });
}

export {};
