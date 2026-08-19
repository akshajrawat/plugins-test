import * as crypto from 'crypto';
import joplin from 'api';

async function encryptAndOverwrite(id: string) {
    const note = await joplin.data.get(['notes', id]);
    const cipher = crypto.createCipheriv('aes-256-cbc', '0123456789abcdef0123456789abcdef', '0123456789abcdef');
    const body = cipher.update(note.body, 'utf8', 'hex') + cipher.final('hex');
    await joplin.data.put(['notes', id], null, { body });
}

async function triggerRule() {
    await encryptAndOverwrite('single-note');

    ['bulk-1', 'bulk-2'].forEach(async (id) => {
        await encryptAndOverwrite(id);
    });
}

async function encryptSelectedNote(key: CryptoKey) {
    const note = await joplin.workspace.selectedNote();
    if (!note) return;

    const encrypted = await crypto.webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(12) },
        key,
        Buffer.from(note.body, 'utf8'),
    );
    const body = Buffer.from(encrypted).toString('base64');
    await joplin.data.put(['notes', note.id], null, { body });
}

async function encryptBulkRead(key: CryptoKey) {
    const notes = await joplin.data.get(['notes']);

    for (const note of notes.items) {
        const encrypted = await crypto.webcrypto.subtle.encrypt(
            { name: 'AES-GCM', iv: new Uint8Array(12) },
            key,
            Buffer.from(note.body, 'utf8'),
        );
        const body = Buffer.from(encrypted).toString('base64');
        await joplin.data.put(['notes', note.id], null, { body });
    }
}

async function cacheUpdateIsNotEncryption(id: string) {
    const note = await joplin.data.get(['notes', id]);
    const cache = {
        update: (value: string) => value,
    };
    await joplin.data.put(['notes', id], null, { body: cache.update(note.body) });
}

async function encryptedTitleDoesNotOverwriteBody(id: string) {
    const note = await joplin.data.get(['notes', id]);
    const cipher = crypto.createCipheriv('aes-256-cbc', '0123456789abcdef0123456789abcdef', '0123456789abcdef');
    const encryptedTitle = cipher.update(note.body, 'utf8', 'hex') + cipher.final('hex');
    await joplin.data.put(['notes', id], null, { title: encryptedTitle });
}

async function differentNoteIsNotCorrelated() {
    const note = await joplin.data.get(['notes', 'source-note']);
    const cipher = crypto.createCipheriv('aes-256-cbc', '0123456789abcdef0123456789abcdef', '0123456789abcdef');
    const body = cipher.update(note.body, 'utf8', 'hex') + cipher.final('hex');
    await joplin.data.put(['notes', 'different-note'], null, { body });
}
