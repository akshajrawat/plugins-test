import * as dgram from 'dgram';
import * as http from 'http';
import * as net from 'net';
import express from 'express';
import fastify from 'fastify';
import { Server as WebSocketServer } from 'ws';

function triggerRule() {
    net.createServer().listen(3000);
    http.createServer().listen(3001, '127.0.0.1');
    dgram.createSocket('udp4').bind(3002);
    express().listen(3003);
    fastify().listen({ port: 3004 });
    (new WebSocketServer({ noServer: true }) as any).listen(3005);
}

export {};
