import {
    BrowserWindow,
    app,
    clipboard,
    dialog,
    ipcMain,
    ipcRenderer,
    screen,
    shell,
} from 'electron';

function triggerRule() {
    new BrowserWindow();
    dialog.showOpenDialog({});
    app.getPath('userData');
    clipboard.readText();
    shell.openExternal('https://example.com');
    ipcRenderer.send('raw-channel');
    ipcMain.on('raw-channel', () => {});
    screen.getPrimaryDisplay();
}

export {};
