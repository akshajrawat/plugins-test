import { remote as electronRemote } from 'electron';
import * as remoteNamespace from '@electron/remote';
import remoteRenderer from '@electron/remote/renderer';
import { initialize } from '@electron/remote/main';

function triggerRule() {
    const remote = require('@electron/remote');
    remote.app.quit();
    electronRemote.app.quit();
    remoteNamespace.app.quit();
    remoteRenderer.app.quit();
    initialize();

    require('electron').remote.getCurrentWindow().close();

    const { remote: destructuredRemote } = require('electron');
    destructuredRemote.getCurrentWindow().close();

    const electron = require('electron');
    electron['remote'].getCurrentWindow().close();
}

function safeCases() {
    const similarlyNamedPackage = require('@electron/remote-control');
    similarlyNamedPackage.connect();

    const localRemote = {
        getCurrentWindow: () => ({ close: () => undefined }),
    };
    localRemote.getCurrentWindow().close();
}
