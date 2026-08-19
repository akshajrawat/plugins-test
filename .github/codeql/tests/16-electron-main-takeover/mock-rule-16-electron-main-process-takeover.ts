import * as remoteNamespace from '@electron/remote';
import * as remoteRenderer from '@electron/remote/renderer';
import { initialize } from '@electron/remote/main';

function triggerRule() {
    const remote = require('@electron/remote');
    remote.app.quit();
    remoteNamespace.app.quit();
    remoteRenderer.getCurrentWindow().close();
    initialize();
}

function safeCases() {
    const similarlyNamedPackage = require('@electron/remote-control');
    similarlyNamedPackage.connect();

    const localRemote = {
        getCurrentWindow: () => ({ close: () => undefined }),
    };
    localRemote.getCurrentWindow().close();
}
