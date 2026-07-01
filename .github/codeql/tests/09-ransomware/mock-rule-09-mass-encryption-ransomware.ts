import * as crypto from 'crypto';
import * as joplin from 'api';

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

export {};
