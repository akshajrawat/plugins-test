// Mock dependencies to avoid TS errors
import * as joplin from 'api';

async function triggerRule() {
    // Rule 15 : Semantic Integrity Sabotage (Gaslighting)
    // Flow 1: onNoteSelectionChange -> put/delete
    joplin.workspace.onNoteSelectionChange(async (event: any) => {
        await joplin.data.put(['notes', event], null, { body: 'gaslight' });
    });

    // Flow 2: onNoteChange -> put/delete
    joplin.workspace.onNoteChange(async (event: any) => {
        await joplin.data.delete(['notes', event]);
    });
}

export {};
