import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import test from 'node:test';
import dnsPacket from 'dns-packet';
import {
    isPublicDnsServerAddress, queryDirectlyUDP,
    resolveHostnameIPv4Self, resolveServerIPs
} from 'dns-self-resolver';

test('固定依存先は非公開のみのNS回答を再利用し診断結果も維持する', async () => {
    let queries = 0;
    const dependencies = {
        isAllowedServerIP: isPublicDnsServerAddress,
        queryDirectlyUDP: async (name, ip, cache, type) => {
            queries++;
            assert.equal(isPublicDnsServerAddress(ip), true);
            return {
                answers: type === 'A' ? [{ name, type, data: '10.0.0.53', ttl: 30 }] : [],
                flags: dnsPacket.AUTHORITATIVE_ANSWER
            };
        }
    };
    assert.equal(await resolveServerIPs('blocked.dependency.test', dependencies), null);
    const completed = queries;
    assert.equal(await resolveHostnameIPv4Self('blocked.dependency.test', dependencies), null);
    assert.equal(await resolveServerIPs('blocked.dependency.test', dependencies), null);
    assert.equal(queries, completed);
    assert.deepEqual(await resolveServerIPs('blocked.dependency.test', {
        ...dependencies, includeBlockedAddresses: true
    }), ['10.0.0.53']);
    assert.equal(queries, completed);
});

async function startDnsStub({ respondToUdp = true, truncateUdp = false } = {}) {
    const tcpServer = net.createServer(socket => {
        let received = Buffer.alloc(0);
        socket.on('data', chunk => {
            received = Buffer.concat([received, chunk]);
            if (received.length < 2) return;

            const messageLength = received.readUInt16BE(0);
            if (received.length < messageLength + 2) return;

            const query = dnsPacket.streamDecode(received);
            const response = makeResponse(query);
            socket.end(dnsPacket.streamEncode(response));
        });
    });
    await new Promise((resolve, reject) => {
        tcpServer.once('error', reject);
        tcpServer.listen(0, '127.0.0.1', resolve);
    });
    const port = tcpServer.address().port;

    const udpServer = dgram.createSocket('udp4');
    udpServer.on('message', (message, remote) => {
        const query = dnsPacket.decode(message);
        if (!respondToUdp) return;
        const response = truncateUdp
            ? {
                type: 'response',
                id: query.id,
                flags: dnsPacket.TRUNCATED_RESPONSE,
                questions: query.questions
            }
            : makeResponse(query);
        udpServer.send(dnsPacket.encode(response), remote.port, remote.address);
    });
    try {
        await new Promise((resolve, reject) => {
            udpServer.once('error', reject);
            udpServer.bind(port, '127.0.0.1', resolve);
        });
    } catch (error) {
        await new Promise(resolve => tcpServer.close(resolve));
        throw error;
    }

    return {
        port,
        close: async () => {
            await Promise.all([
                new Promise(resolve => udpServer.close(resolve)),
                new Promise(resolve => tcpServer.close(resolve))
            ]);
        }
    };
}

function makeResponse(query) {
    return {
        type: 'response',
        id: query.id,
        flags: dnsPacket.AUTHORITATIVE_ANSWER,
        questions: query.questions,
        answers: [{
            type: 'A',
            name: query.questions[0].name,
            ttl: 30,
            data: '198.51.100.7'
        }]
    };
}

async function withDnsStub(options, callback) {
    const server = await startDnsStub(options);
    try {
        await callback(server);
    } finally {
        await server.close();
    }
}

test('dns-self-resolver は非特権ポートのローカル DNS 応答を decode する', async () => {
    await withDnsStub({}, async ({ port }) => {
        const response = await queryDirectlyUDP(
            'ordinary.integration.test',
            '127.0.0.1',
            new Map(),
            'A',
            { udpPort: port, tcpPort: port, timeoutMs: 1000, useEdns: false, use0x20: false }
        );

        assert.equal(response.error, undefined);
        assert.equal(response.transport, 'udp');
        assert.equal(response.rcode, 'NOERROR');
        assert.equal(response.answers[0].data, '198.51.100.7');
    });
});

test('dns-self-resolver は UDP の TC 応答を TCP で再試行する', async () => {
    await withDnsStub({ truncateUdp: true }, async ({ port }) => {
        const response = await queryDirectlyUDP(
            'truncated.integration.test',
            '127.0.0.1',
            new Map(),
            'A',
            { udpPort: port, tcpPort: port, timeoutMs: 1000, useEdns: false, use0x20: false }
        );

        assert.equal(response.error, undefined);
        assert.equal(response.transport, 'tcp');
        assert.equal(response.retryFrom, 'udp-truncated');
        assert.equal(response.isFallback, true);
        assert.equal(response.answers[0].data, '198.51.100.7');
    });
});

test('dns-self-resolver はタイムアウトと AbortSignal を結果として返す', async t => {
    await withDnsStub({ respondToUdp: false }, async ({ port }) => {
        await t.test('タイムアウト', async () => {
            const response = await queryDirectlyUDP(
                'timeout.integration.test',
                '127.0.0.1',
                new Map(),
                'A',
                { udpPort: port, tcpPort: port, timeoutMs: 50, useEdns: false, use0x20: false }
            );
            assert.equal(response.error, 'TIMEOUT');
            assert.equal(response.transport, 'udp');
        });

        await t.test('中断', async () => {
            const controller = new AbortController();
            const query = queryDirectlyUDP(
                'abort.integration.test',
                '127.0.0.1',
                new Map(),
                'A',
                { udpPort: port, tcpPort: port, timeoutMs: 1000, useEdns: false, use0x20: false, signal: controller.signal }
            );
            setTimeout(() => controller.abort(), 20);
            const response = await query;
            assert.equal(response.error, 'ABORTED');
            assert.equal(response.transport, 'udp');
        });
    });
});
