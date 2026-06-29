// FROM : 
// joplin.data.get(['notes', '123']) / joplin.data.get(['notes', '456']) / joplin.workspace.selectedNote()
// 
// TO : 
// joplin.data.put

import * as joplin from 'api';
import * as myCrypto from 'crypto';

async function triggerRule() {
    const s1 = await joplin.data.get(['notes', '123']);
    
    const c1 = myCrypto.createCipheriv('aes', 'key', 'iv');
    const e1a = c1.update(s1.body, 'utf8', 'hex') + c1.final('hex');
    await joplin.data.put(['notes', s1.id], null, { body: e1a });

    const cryptoJsLike1 = { encrypt: (data: string, key: string) => 'enc_' + data };
    const e1b = cryptoJsLike1.encrypt(s1.body, 'secret');
    await joplin.data.put(['notes', s1.id], null, { body: e1b });

    const s2 = await joplin.workspace.selectedNote();
    
    const c2 = myCrypto.createCipheriv('aes', 'key', 'iv');
    const e2a = c2.update(s2.body, 'utf8', 'hex') + c2.final('hex');
    await joplin.data.put(['notes', s2.id], null, { body: e2a });

    const cryptoJsLike2 = { encrypt: (data: string, key: string) => 'enc_' + data };
    const e2b = cryptoJsLike2.encrypt(s2.body, 'secret');
    await joplin.data.put(['notes', s2.id], null, { body: e2b });
    
    const s3 = await joplin.data.get(['notes', '456']);
    
    const c3 = myCrypto.createCipheriv('aes', 'key', 'iv');
    const e3a = c3.update(s3.body, 'utf8', 'hex') + c3.final('hex');
    await joplin.data.put(['notes', '456'], null, { body: e3a });

    const cryptoJsLike3 = { encrypt: (data: string, key: string) => 'enc_' + data };
    const e3b = cryptoJsLike3.encrypt(s3.body, 'secret');
    await joplin.data.put(['notes', '456'], null, { body: e3b });
}

export { };