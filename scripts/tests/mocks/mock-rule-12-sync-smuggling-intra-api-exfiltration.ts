// Mock dependencies to avoid TS errors
import * as joplin from 'api';

async function triggerRule() {
    // Rule 12 : Sync Smuggling (Intra-API Exfiltration)
    // Flow 1: notes -> userDataSet
    const r12f1 = await joplin.data.get(['notes', '1']);
    await joplin.data.userDataSet(r12f1.body);

    // Flow 2: folders/resources/master_keys -> userDataSet
    const r12f2 = await joplin.data.get(['master_keys', '1']);
    await joplin.data.userDataSet(r12f2.content);
}

export {};
