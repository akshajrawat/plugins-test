// Mock dependencies to avoid TS errors
import * as joplin from 'api';

async function triggerRule() {
    // Rule 17b : Unsafe Archive Extraction Destination
    // Flow 1 & 2: extract without dataDir
    await joplin.fs.archiveExtract('safe.zip', '/etc/passwd');
}

export {};
