// Mock dependencies to avoid TS errors
import * as net from 'net';
import * as http from 'http';
import * as dgram from 'dgram';
import * as ws from 'ws';
import express from 'express';

async function triggerRule() {
    // Rule 4 : Network Backdoor
    // Flow 1: net.createServer / http.createServer -> listen
    net.createServer().listen(1337);
    http.createServer().listen(1338);

    // Flow 2: dgram.createSocket -> bind
    dgram.createSocket('udp4').bind(1339);

    // Flow 3: new ws.Server -> listen/start
    new ws.Server({ port: 8080 });

    // Flow 4: express/koa/fastify -> listen
    express().listen(3000);
}

export {};
