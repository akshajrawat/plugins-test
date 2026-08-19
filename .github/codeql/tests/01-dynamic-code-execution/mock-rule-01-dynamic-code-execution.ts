import * as http from 'http';
import * as https from 'https';
import * as nodeHttp from 'node:http';
import * as vm from 'vm';
import joplin from 'api';
import axios from 'axios';
import got from 'got';
import superagent from 'superagent';
import { WebSocket } from 'ws';
import { MessageChannel, Worker } from 'worker_threads';
import { ModelType } from 'api/types';

async function remoteRequestSources(url: string) {
    const res = await fetch(url);
    eval(await res.text());

    const axiosGetResponse = await axios.get(url);
    new Function(axiosGetResponse.data)();

    const axiosPostResponse = await axios.post(url, {});
    Function(axiosPostResponse.data)();

    const axiosParameterResponse = await axios.get(url);
    Function(axiosParameterResponse.data, 'return 1;')();

    const axiosCallResponse = await axios({ method: 'get', url });
    vm.runInThisContext(axiosCallResponse.data);

    const gotResponse = await got(url);
    vm.runInContext(gotResponse.body, vm.createContext({}));

    superagent.get(url).then((reply: any) => {
        vm.runInNewContext(reply.text);
    });

    superagent.get(url).end((_error: Error | null, reply: any) => {
        new vm.Script(reply.text);
    });
}

function httpStreamSources(url: string) {
    http.get(url, response => {
        response.on('data', chunk => {
            eval(chunk.toString());
        });
    });

    https.request(url, response => {
        response.on('data', chunk => {
            vm.runInThisContext(chunk.toString());
        });
    }).end();

    nodeHttp.get(url, response => {
        response.on('data', chunk => {
            setTimeout(chunk.toString());
        });
    });
}

async function persistedDataSource() {
    const stored = await joplin.data.userDataGet<string>(ModelType.Note, '1', 'payload');
    setInterval(stored);
}

function eventSources(url: string, panel: string, contentScriptId: string) {
    window.addEventListener('message', event => {
        eval(event.data);
    });

    new WebSocket(url).on('message', message => {
        Function(message)();
    });

    new Worker('./worker.js').on('message', message => {
        setTimeout(message);
    });

    new MessageChannel().port1.on('message', message => {
        setInterval(message);
    });

    joplin.views.panels.onMessage(panel, (message: any) => {
        vm.compileFunction(message, []);
    });

    joplin.contentScripts.onMessage(contentScriptId, (message: any) => {
        new vm.Script(message);
    });
}

async function safeCases(url: string) {
    const response = await fetch(url);
    console.info(await response.text());

    eval('const localValue = 1;');

    window.addEventListener('click', event => {
        console.info(event.type);
    });
}
