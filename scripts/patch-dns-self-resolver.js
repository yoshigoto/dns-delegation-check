import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const packageDirectory = path.join(rootDirectory, 'node_modules', 'dns-self-resolver');
const packageJson = JSON.parse(fs.readFileSync(path.join(packageDirectory, 'package.json'), 'utf8'));

if (packageJson.version !== '1.1.2') {
    throw new Error(`dns-self-resolver patch expects version 1.1.2; found ${packageJson.version}`);
}

const sourcePath = path.join(packageDirectory, 'index.js');
let source = fs.readFileSync(sourcePath, 'utf8');
const replacements = [
    [
        "return `${serverIp}|${qType}|${domain}|edns:${options.useEdns ? 1 : 0}|do:${options.dnssecOk ? 1 : 0}|timeout:${options.timeoutMs}`;",
        "return `${serverIp}|${qType}|${domain}|port:${options.port ?? DNS_PORT}|edns:${options.useEdns ? 1 : 0}|do:${options.dnssecOk ? 1 : 0}|timeout:${options.timeoutMs}`;"
    ],
    [
        "        timeoutMs: 5000\n    });\n\n    return new Promise((resolve) => {",
        "        timeoutMs: 5000\n    });\n    const dnsPort = options.port ?? DNS_PORT;\n\n    return new Promise((resolve) => {"
    ],
    [
        "net.createConnection({ host: serverIp, port: 53 }, () => {",
        "net.createConnection({ host: serverIp, port: dnsPort }, () => {"
    ],
    [
        "function performUdpQuery(domain, serverIp, dnsResponseCache, qType, options) {\n    return new Promise((resolve) => {",
        "function performUdpQuery(domain, serverIp, dnsResponseCache, qType, options) {\n    const dnsPort = options.port ?? DNS_PORT;\n    return new Promise((resolve) => {"
    ],
    [
        "(rinfo.port !== undefined && rinfo.port !== DNS_PORT)",
        "(rinfo.port !== undefined && rinfo.port !== dnsPort)"
    ],
    [
        "client.send(buf, 0, buf.length, DNS_PORT, serverIp, (err) => {",
        "client.send(buf, 0, buf.length, dnsPort, serverIp, (err) => {"
    ]
];

for (const [original, patched] of replacements) {
    if (source.includes(patched)) continue;
    const firstIndex = source.indexOf(original);
    if (firstIndex === -1 || source.indexOf(original, firstIndex + original.length) !== -1) {
        throw new Error(`Could not apply dns-self-resolver port patch: ${original}`);
    }
    source = source.replace(original, patched);
}

fs.writeFileSync(sourcePath, source);
