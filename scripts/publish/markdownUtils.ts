export const escapeMarkdownText = async (value: string) => {
    return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
};

export const escapeInlineCode = async (value: string) => {
    return value.replace(/`/g, '\\`');
};

export const escapeMarkdownUrl = async (value: string) => {
    return value.replace(/\(/g, '%28').replace(/\)/g, '%29');
};
