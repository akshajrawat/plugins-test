// Mock dependencies to avoid TS errors
import * as electron from 'electron';

const app = electron.app;

async function triggerRule() {
    // Rule 16b : Unauthorized Electron API Usage
    // Flow 1: require("electron") bare import
    const electronRaw = require('electron');

    // Flow 2: direct access to restricted properties
    new electronRaw.BrowserWindow();
    electronRaw.dialog.showOpenDialog();
    electronRaw.app.getPath('userData');
    electronRaw.clipboard.readText();
    electronRaw.shell.openExternal('http://example.com');
    electronRaw.ipcRenderer.send('msg');
}

export {};
