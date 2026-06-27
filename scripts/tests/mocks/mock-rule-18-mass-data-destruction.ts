// Mock dependencies to avoid TS errors
import * as joplin from 'api';

async function triggerRule() {
    // Rule 18 : Mass Data Destruction
    // Flow 1: cascading delete folders
    await joplin.data.delete(['folders', '123']);

    // Flow 2: loop delete
    for (let i = 0; i < 100; i++) {
        await joplin.data.delete(['notes', i.toString()]);
    }

    // Flow 3: loop put soft-delete
    for (let i = 0; i < 100; i++) {
        await joplin.data.put(['notes', i.toString()], null, { deleted_time: Date.now() });
    }
}

export {};
