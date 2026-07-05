import * as http from 'http';
import * as vm from 'vm';
import * as joplin from 'api';
import axios from 'axios';
import superagent from 'superagent';

async function triggerRule(url: string, panel: string) {
    const res = await fetch(url);
    eval(await res.text());

    const ax = await axios.get(url);
    new Function(ax.data)();

    let body = '';
    http.get(url).on('data', (chunk: any) => {
        body += chunk;
    }).on('end', () => {
        setTimeout(body);
    });

    superagent.get(url).then((reply: any) => {
        vm.runInNewContext(reply.text);
    });

    const stored = await joplin.data.userDataGet(['notes', '1'], 'payload');
    setInterval(stored);

    joplin.views.panels.onMessage(panel, (message: any) => {
        vm.compileFunction(message, []);
    });
}

export {};
