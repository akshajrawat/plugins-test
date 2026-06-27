
async function triggerRule() {
    // Rule 17d : Third-Party Archive Extraction
    // Flow 1: usage of external unarchiver
    require('extract-zip');
    require('yauzl');
    require('adm-zip');
    require('tar');
}

export {};
