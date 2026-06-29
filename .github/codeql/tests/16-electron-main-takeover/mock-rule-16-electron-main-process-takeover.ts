// FROM : 
// require('@electron/remote') / require('electron').remote
// 
// TO : 
// app.quit() / remote.app.quit()

import * as electron from 'electron';

const app = electron.app;

async function triggerRule() {
    require('@electron/remote').app.quit();
    require('electron').remote.app.quit();
}

export {};
