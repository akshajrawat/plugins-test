// Mock dependencies to avoid TS errors
import * as electron from 'electron';

const app = electron.app;

async function triggerRule() {
    // Rule 16 : Electron Main Process Takeover
    // Flow 1: require("@electron/remote")
    require('@electron/remote').app.quit();

    // Flow 2: require("electron").remote
    require('electron').remote.app.quit();
}

export {};
