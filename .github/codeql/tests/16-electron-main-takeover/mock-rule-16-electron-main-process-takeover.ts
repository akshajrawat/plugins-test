import { remote as electronRemote } from 'electron';

function triggerRule() {
    const remote = require('@electron/remote');
    remote.app.quit();
    electronRemote.app.quit();
    require('electron').remote.getCurrentWindow().close();
}
