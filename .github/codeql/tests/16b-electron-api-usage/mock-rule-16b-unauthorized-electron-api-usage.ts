// FROM : 
// require('electron')
// 
// TO : 
// new BrowserWindow() / dialog.showOpenDialog / app.getPath / clipboard.readText / shell.openExternal / ipcRenderer.send

import * as electron from 'electron';

const app = electron.app;

async function triggerRule() {
    const electronRaw = require('electron');
    new electronRaw.BrowserWindow();
    electronRaw.dialog.showOpenDialog();
    electronRaw.app.getPath('userData');
    electronRaw.clipboard.readText();
    electronRaw.shell.openExternal('http://example.com');
    electronRaw.ipcRenderer.send('msg');
}

export {};
