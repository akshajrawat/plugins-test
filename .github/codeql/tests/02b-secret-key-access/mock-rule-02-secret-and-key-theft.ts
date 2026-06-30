import * as joplin from 'api';

async function triggerRule() {
    // CONDITION 1: standalone highly sensitive access

    await joplin.settings.globalValue('api.token');

    await joplin.settings.globalValue('encryption.cachedPpk');

    await joplin.settings.globalValue('encryption.passwordCache');

    await joplin.settings.globalValue('sync.5.password');

    // Array access should also trigger
    await joplin.settings.globalValues([
        'api.token',
        'encryption.cachedPpk',
        'encryption.passwordCache',
        'sync.6.password',
    ]);

    // CONDITION 2: combined access of masterPassword + syncInfoCache

    await joplin.settings.globalValue('encryption.masterPassword');

    await joplin.settings.globalValue('syncInfoCache');

    // Array version of combined access
    await joplin.settings.globalValues([
        'encryption.masterPassword',
        'syncInfoCache',
    ]);

    // Negative: should NOT trigger
    await joplin.settings.globalValue('theme');

    await joplin.settings.globalValue('locale');

    await joplin.settings.globalValues([
        'theme',
        'locale',
    ]);
}

triggerRule();