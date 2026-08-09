import * as childProcess from 'child_process';
import { execa } from 'execa';

function hardcodedCommands() {
    childProcess.exec('echo reviewed');
    childProcess.spawn('node', ['--version']);
    childProcess.spawn('git', ['clean', '-fdx']);
    childProcess.execFileSync('ffmpeg', ['-version']);

    const assignedCommand = 'python';
    childProcess.execFile(assignedCommand, ['script.py']);

    execa('node', ['--version']);
}

function cryptominingCommandsOwnedByRule6() {
    childProcess.exec('xmrig --url stratum+tcp://pool.example:3333');
    childProcess.spawn('node', ['miner.js', 'stratum+tcp://pool.example:3333']);
}

function safeCases() {
    const description = 'echo reviewed';
    console.info(description);

    const dynamicCommand = process.env.PLUGIN_COMMAND;
    if (dynamicCommand) {
        childProcess.spawn(dynamicCommand, [], {
            env: { DESCRIPTION: 'xmrig' },
        });
    }
}
