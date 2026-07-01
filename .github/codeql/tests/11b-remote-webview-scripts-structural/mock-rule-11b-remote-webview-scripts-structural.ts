import * as joplin from 'api';

async function triggerRule(panel: string, dialog: string, editor: string) {
    await joplin.views.panels.setHtml(panel, '<script src="https://cdn.example/payload.js"></script>');
    await joplin.views.dialogs.setHtml(dialog, '<link href="https://cdn.example/theme.css" rel="stylesheet">');
    await joplin.views.editors.setHtml(editor, '<style>body{background:url(https://cdn.example/bg.png)}</style>');
}

export {};
