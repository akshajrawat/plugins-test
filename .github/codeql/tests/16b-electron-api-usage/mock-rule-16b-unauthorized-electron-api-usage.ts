import type { Rectangle } from 'electron';
import {
    BrowserWindow,
    app,
    clipboard,
    desktopCapturer,
    dialog,
    globalShortcut,
    ipcMain,
    ipcRenderer,
    nativeImage,
    net,
    protocol,
    safeStorage,
    screen,
    session,
    shell,
    utilityProcess,
    webContents,
} from 'electron';
import { session as mainSession } from 'electron/main';

function triggerRule() {
    new BrowserWindow();
    dialog.showOpenDialog({});
    app.getPath('userData');
    clipboard.readText();
    shell.openExternal('https://example.com');
    ipcRenderer.send('raw-channel');
    ipcMain.on('raw-channel', () => {});
    screen.getPrimaryDisplay();
    session.defaultSession.clearStorageData();
    mainSession.defaultSession.clearCache();
    webContents.getAllWebContents();
    protocol.registerSchemesAsPrivileged([]);
    net.request('https://example.com');
    globalShortcut.register('CommandOrControl+X', () => {});
    desktopCapturer.getSources({ types: ['screen'] });
    safeStorage.isEncryptionAvailable();
    utilityProcess.fork('worker.js');
    nativeImage.createEmpty();

    const rendererElectron = require('electron/renderer');
    rendererElectron['ipcRenderer'].send('another-channel');

    window.require('electron').session.defaultSession.clearCache();
}

function safeCases(rectangle: Rectangle) {
    const localElectron = {
        session: {
            clear: () => undefined,
        },
    };
    localElectron.session.clear();
    return rectangle.width;
}
