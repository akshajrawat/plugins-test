// Mock dependencies to avoid TS errors
import * as joplin from 'api';
import axios from 'axios';
import * as path from 'path';

// ==========================================
// MOCK SAFE PLUGINS (Should NOT trigger vulnerabilities)
// ==========================================

async function mockSafePlugins() {
    // 1. joplin-exports-to-ssg
    const fs = joplin.require('fs-extra');
    const path = require('path');
    const dest = '/mock/dest';
    await fs.mkdirp(path.join(dest, 'content'));
    fs.copy('/mock/src', dest);

    // 2. joplin-note-statistics
    const note = await joplin.workspace.selectedNote();
    const words = note.body.split(' ').length;
    await joplin.views.dialogs.setHtml('handle', `<p>Words: ${words}</p>`);

    // 3. joplin-plugin-fold-cm
    await joplin.contentScripts.register('CodeMirrorPlugin', 'folding', './folding.js');
    await joplin.commands.register({
        name: 'foldAll',
        execute: async () => {
            await joplin.commands.execute('editor.execCommand', { name: 'foldAll' });
        }
    });

    // 4. joplin-plugin-jira-issue
    const host = await joplin.settings.value('jiraHost');
    const password = await joplin.settings.value('password');
    await axios.get(host + '/rest/api/latest/issue', {
        headers: { Authorization: 'Bearer ' + password }
    });

    // 5. joplin-quick-move
    const noteIds = await joplin.workspace.selectedNoteIds();
    for (const id of noteIds) {
        await joplin.data.put(['notes', id], null, { parent_id: 'mock-folder' });
    }
}

export {};
