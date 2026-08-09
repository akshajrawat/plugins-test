import * as joplin from 'api';

const deleteLoopNote = (id: string) => {
    joplin.data.delete(['notes', id]);
};

const deleteRecursiveNote = (id: string) => {
    joplin.data.delete(['notes', id]);
};

const markDeleted = (id: string) => {
    joplin.data.put(['notes', id], null, { deleted_time: Date.now() });
};

function deleteForever() {
    while (true) {
        deleteLoopNote('loop-note');
    }
}

function repeatDelete() {
    deleteRecursiveNote('recursive-note');
    setTimeout(repeatDelete, 1000);
}

async function dialogDoesNotSuppressFinding() {
    await joplin.views.dialogs.open('confirmation-dialog');
    joplin.data.delete(['folders', 'still-reported']);
}

async function triggerRule() {
    joplin.data.delete(['folders', 'archive']);

    ['n1', 'n2'].forEach((id) => {
        markDeleted(id);
    });

    setInterval(() => {
        joplin.data.put(['notes', 'blank'], null, { body: '' });
    }, 1000);

    ['conflict-1', 'conflict-2'].forEach((id) => {
        joplin.data.put(['notes', id], null, { is_conflict: true });
    });

    for (const id of ['empty-1', 'empty-2']) {
        joplin.data.put(['notes', id], null, { deleted_time: 1 });
    }

    repeatDelete();
    await dialogDoesNotSuppressFinding();
}

function safeOperations() {
    joplin.data.delete(['notes', 'single-note']);
    joplin.data.delete(['folders', 'folder-id', 'notes']);

    for (const id of ['safe-1', 'safe-2']) {
        joplin.data.put(['notes', id], null, { deleted_time: 0 });
        joplin.data.put(['notes', id], null, { is_conflict: false });
        joplin.data.put(['notes', id], null, { body: 'Preserved content' });
    }
}
