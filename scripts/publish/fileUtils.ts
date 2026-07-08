import { createHash } from 'crypto';
import { access, readFile, writeFile } from 'fs/promises';
import { resolve } from 'path';

export const fileExists = async (path: string) => {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
};

export const getRegistryPath = async (relativePath: string) => {
    const workspace = process.env.GITHUB_WORKSPACE;
    const candidates = [
        workspace ? resolve(workspace, 'plugins-test', relativePath) : '',
        resolve(process.cwd(), 'plugins-test', relativePath),
        resolve(process.cwd(), relativePath),
        resolve(__dirname, '..', '..', relativePath),
    ].filter(Boolean);

    for (const candidate of candidates) {
        if (await fileExists(candidate)) return candidate;
    }

    return candidates[0];
};

export const readJsonFile = async <T>(path: string, defaultValue: T): Promise<T> => {
    if (!(await fileExists(path))) return defaultValue;
    return JSON.parse(await readFile(path, 'utf8')) as T;
};

export const readJsonFromFile = async (path: string) => {
    return JSON.parse(await readFile(path, 'utf8'));
};

export const writeJsonFile = async (path: string, value: unknown) => {
    await writeFile(path, `${JSON.stringify(value, null, '\t')}\n`, 'utf8');
};

export const sha256File = async (path: string) => {
    const hash = createHash('sha256');
    hash.update(await readFile(path));
    return `sha256:${hash.digest('hex')}`;
};
