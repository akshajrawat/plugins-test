import joplin from 'api';

async function triggerRule() {
    await joplin.settings.globalValue('api.token');
    await joplin.settings.globalValue('encryption.cachedPpk');
    await joplin.settings.globalValue('encryption.passwordCache');
    await joplin.settings.globalValue('sync.5.password');

    await joplin.settings.globalValues([
        'api.token',
        'encryption.cachedPpk',
        'sync.6.password',
    ]);

    await joplin.settings.globalValue('encryption.masterPassword');
    await joplin.settings.globalValue('syncInfoCache');

    await joplin.settings.globalValues([
        'encryption.masterPassword',
        'syncInfoCache',
    ]);

    await joplin.settings.globalValue('apiXtoken');
    await joplin.settings.globalValue('theme');
}
