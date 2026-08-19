import * as http from 'http';
import * as nodeHttps from 'node:https';
import joplin from 'api';
import axios from 'axios';
import got from 'got';
import superagent from 'superagent';

async function clipboardSources() {
    const copiedText = await joplin.clipboard.readText();
    await joplin.clipboard.writeText(copiedText.toUpperCase());
    await joplin.clipboard.writeHtml(`<b>${copiedText}</b>`);

    const copiedHtml = await joplin.clipboard.readHtml();
    await joplin.clipboard.write({ html: copiedHtml });

    const copiedImage = await joplin.clipboard.readImage();
    await joplin.clipboard.writeImage(copiedImage);
}

async function remoteRequestSources(url: string) {
    const fetchResponse = await fetch(url);
    await joplin.clipboard.writeText(await fetchResponse.text());

    const axiosResponse = await axios.patch(url, {});
    await joplin.clipboard.writeHtml(axiosResponse.data);

    const axiosClient = axios.create();
    const clientResponse = await axiosClient.get(url);
    await joplin.clipboard.writeText(clientResponse.data);

    const gotResponse = await got.post(url);
    await joplin.clipboard.write({ text: gotResponse.body });

    superagent.get(url).then(async (response: any) => {
        await joplin.clipboard.writeText(response.body);
    });

    superagent.post(url).end(async (_error: Error | null, response: any) => {
        await joplin.clipboard.writeImage(response.text);
    });
}

function nodeHttpSources(url: string) {
    http.get(url, response => {
        response.on('data', async chunk => {
            await joplin.clipboard.writeText(chunk.toString());
        });
    });

    nodeHttps.request(url, response => {
        response.on('data', async chunk => {
            await joplin.clipboard.writeHtml(chunk.toString());
        });
    }).end();
}

async function safeCases(url: string) {
    await joplin.clipboard.writeText('Locally generated text');
    await joplin.clipboard.write({ html: '<strong>Local HTML</strong>' });

    const response = await fetch(url);
    console.info(await response.text());

    const copied = await joplin.clipboard.readText();
    console.info(copied);

    const unrelatedClipboard = {
        readText: () => 'Unrelated text',
        writeText: (_text: string) => {},
    };
    unrelatedClipboard.writeText(unrelatedClipboard.readText());
}
