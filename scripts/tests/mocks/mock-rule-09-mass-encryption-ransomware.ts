// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import * as myCrypto from 'crypto';

async function triggerRule() {
    // Rule 9 : Mass Encryption / Ransomware
    // Flow 1, 2, 3, 4: read -> encrypt -> write back (same note)
    const r9note = await joplin.data.get(['notes', '123']);
    const r9cipher = myCrypto.createCipheriv('aes', 'key', 'iv');
    const r9enc = r9cipher.update(r9note.body, 'utf8', 'hex') + r9cipher.final('hex');
    await joplin.data.put(['notes', r9note.id], null, { body: r9enc });
}

export {};
