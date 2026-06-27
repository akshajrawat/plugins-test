
async function triggerRule() {
    // Rule 20 : Native Module Imports
    // Flow 1: require of fs, net, os, dgram, child_process, tls, http, https, sqlite3, better-sqlite3
    require('fs');
    require('net');
    require('os');
    require('dgram');
    require('child_process');
    require('tls');
    require('http');
    require('https');
    require('sqlite3');
    require('better-sqlite3');
    require('node:fs');
}

export {};
