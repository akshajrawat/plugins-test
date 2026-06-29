// FROM : 
// net.createServer() / http.createServer() / https.createServer() / tls.createServer() / dgram.createSocket() / ws.Server / express() / Koa / fastify()
// 
// TO : 
// listen / bind

import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import * as tls from 'tls';
import * as dgram from 'dgram';
import * as ws from 'ws';
import express from 'express';
import Koa from 'koa';
import fastify from 'fastify';

async function triggerRule() {
    net.createServer().listen(1337);
    http.createServer().listen(1338);
    https.createServer().listen(1340);
    tls.createServer().listen(1341);
    dgram.createSocket('udp4').bind(1339);

    const wsServer = new ws.Server({ noServer: true });
    (wsServer as any).listen(8080);

    express().listen(3000);

    const koaApp1 = (Koa as any)();
    koaApp1.listen(3001);

    const koaApp2 = new (Koa as any)();
    koaApp2.listen(3002);

    const fastifyApp = fastify();
    (fastifyApp as any).listen(3003);
}

export { };