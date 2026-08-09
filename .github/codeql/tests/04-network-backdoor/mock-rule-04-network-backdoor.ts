import * as dgram from 'dgram';
import * as http from 'http';
import * as net from 'net';
import express from 'express';
import fastify from 'fastify';
import Koa from 'koa';
import { Server as SocketIoServer } from 'socket.io';
import { WebSocketServer } from 'ws';

function triggerRule() {
    net.createServer().listen(3000);
    http.createServer().listen(3001, '127.0.0.1');
    dgram.createSocket('udp4').bind({ port: 3002, address: '127.0.0.1' });
    express().listen(3003);
    fastify().listen({ port: 3004, host: 'localhost' });
    new Koa().listen(3005);
    new WebSocketServer({ port: 3006 });
    new WebSocketServer({ port: 3007, host: '::1' });
    new SocketIoServer(3008);

    http.createServer();
    new WebSocketServer({ noServer: true });
    new SocketIoServer();
}

export { };
