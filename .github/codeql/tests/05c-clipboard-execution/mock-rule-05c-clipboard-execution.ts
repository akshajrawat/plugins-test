import * as childProcess from 'child_process';
import * as joplin from 'api';
import * as vm from 'node:vm';

async function javascriptExecution() {
    const copiedText = await joplin.clipboard.readText();
    eval(copiedText);
    Function(copiedText)();
    new Function(copiedText)();
    new Function('value', copiedText)('test');
    setTimeout(copiedText, 100);
    setInterval(copiedText, 100);

    const copiedHtml = await joplin.clipboard.readHtml();
    vm.runInThisContext(copiedHtml);
    vm.runInNewContext(copiedHtml);
    vm.runInContext(copiedHtml, vm.createContext({}));
    vm.compileFunction(copiedHtml, []);
    new vm.Script(copiedHtml);
}

async function commandExecution() {
    const copiedText = await joplin.clipboard.readText();
    childProcess.exec(copiedText);
    childProcess.execSync(copiedText);
    childProcess.spawn(copiedText);
}

async function safeCases() {
    const copiedText = await joplin.clipboard.readText();
    console.info(copiedText);

    eval('const localValue = 1;');
    setTimeout(() => console.info(copiedText), 100);
    setInterval(() => console.info('Local callback'), 100);

    const parser = {
        eval: (value: string) => console.info(value),
    };
    parser.eval(copiedText);

    const scheduler = {
        setTimeout: (value: string) => console.info(value),
        setInterval: (value: string) => console.info(value),
    };
    scheduler.setTimeout(copiedText);
    scheduler.setInterval(copiedText);
}
