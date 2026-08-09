import * as joplin from 'api';

async function triggerRule(panel: string, dialog: string, editor: string) {
    const scriptPath = 'payload.js';
    await joplin.views.panels.setHtml(panel, `<script src="https://cdn.example/${scriptPath}"></script>`);
    await joplin.views.dialogs.setHtml(dialog, '<link href="https://cdn.example/theme.css" rel="stylesheet">');
    await joplin.views.editors.setHtml(editor, '<style>body{background:url(https://cdn.example/bg.png)}</style>');
    await joplin.views.panels.setHtml(panel, '<iframe src="https://cdn.example/frame"></iframe>');
    await joplin.views.dialogs.setHtml(dialog, '<meta http-equiv="refresh" content="0;url=https://cdn.example/next">');
    await joplin.views.editors.setHtml(editor, '<meta content="0.5; url=https://cdn.example/next" http-equiv="refresh">');
}

async function safeCases(panel: string) {
    await joplin.views.panels.setHtml(panel, '<script src="http://localhost:41184/local.js"></script>');
    await joplin.views.panels.setHtml(panel, '<img src="https://cdn.example/image.png">');
    await joplin.views.panels.setHtml(panel, '<p>Locally generated content</p>');

    const unrelatedView = {
        setHtml: (_handle: string, _html: string) => {},
    };
    unrelatedView.setHtml(panel, '<script src="https://cdn.example/unrelated.js"></script>');
}
