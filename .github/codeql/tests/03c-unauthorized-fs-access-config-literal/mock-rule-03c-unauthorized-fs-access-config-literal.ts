import * as fs from 'fs';
import * as joplin from 'api';
import * as path from 'path';

async function triggerRule() {
    fs.writeFileSync('/home/user/.config/joplin-desktop/database.sqlite', 'patched');
    fs.readFileSync(path.join('/home/user', '.ssh', 'config'));
    fs.readFileSync('/home/user/keys/id_rsa');
    fs.appendFileSync('/home/user/keys/authorized_keys', 'attacker-key');

    fs.writeFileSync('/tmp/log.txt', 'database.sqlite');
    fs.writeFileSync('/tmp/database.sqlite', 'plugin database');
    fs.writeFileSync('/tmp/not_id_rsa.txt', 'unrelated');
    fs.writeFileSync('/tmp/.ssh-notes', 'unrelated');

    await joplin.fs.archiveExtract('plugin.zip', '/home/user/.ssh');
}
