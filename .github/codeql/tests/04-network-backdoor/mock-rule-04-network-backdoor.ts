import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import * as tls from 'tls';
import * as dgram from 'dgram';
import express from 'express';
import Koa from 'koa';
import fastify from 'fastify';
import { Server as WebSocketServer } from 'ws';

function triggerRule() {
    // Positive: Node servers opening listeners

    const netServer = net.createServer();
    netServer.listen(3000);

    const httpServer = http.createServer();
    httpServer.listen(3001);

    const httpsServer = https.createServer();
    httpsServer.listen(3002);

    const tlsServer = tls.createServer();
    tlsServer.listen(3003);

    const udpSocket = dgram.createSocket('udp4');
    udpSocket.bind(41234);

    // Positive: chained calls

    net.createServer().listen(4000);
    http.createServer().listen(4001);
    https.createServer().listen(4002);
    tls.createServer().listen(4003);
    dgram.createSocket('udp4').bind(4004);

    // Positive: framework servers

    const expressApp = express();
    expressApp.listen(5000);

    const koaApp = new Koa();
    koaApp.listen(5001);

    const koaApp2 = Koa();
    koaApp2.listen(5002);

    const fastifyApp = fastify();
    fastifyApp.listen({ port: 5003 });

    // This only reports if your rule tracks new ws.Server() -> .listen/.bind.
    // Note: ws.Server usually opens via constructor options, so this pattern may not be realistic.
    const wsServer = new WebSocketServer({ noServer: true });
    wsServer.listen(5004 as any);

    // Negative: client outbound connections should not report

    net.connect(80, 'example.com');
    http.request('http://example.com');
    https.request('https://example.com');

    // Negative: unrelated object with listen() should not report

    const fake = {
        listen(port: number) {
            return port;
        },
        bind(port: number) {
            return port;
        },
    };

    fake.listen(9999);
    fake.bind(9998);
}

triggerRule();