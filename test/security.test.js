import assert from 'node:assert/strict';
import test from 'node:test';

import {
    app,
    getZoneApex,
    isPublicServerIP,
    traceDomain
} from '../dns-delegation-check.js';

const isTestNetAllowed = ip => ip.startsWith('192.0.2.');

test('isPublicServerIP はグローバルユニキャストアドレスのみ許可する', () => {
    for (const ip of ['198.41.0.4', '8.8.8.8', '2001:503:ba3e::2:30', '2a00:1450:4001::1']) {
        assert.equal(isPublicServerIP(ip), true, ip);
    }
    for (const ip of [
        '', 'example.com', '0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.169.254',
        '172.16.0.1', '172.31.255.255', '192.0.0.8', '192.0.2.1', '192.168.1.1', '198.18.0.1',
        '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
        '::', '::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', 'fc00::1', 'fd12::1',
        'fe80::1', 'fe80::1%eth0', 'ff02::1', '2001:db8::1', '2001::1', '2002:7f00:1::1', '3fff::1'
    ]) {
        assert.equal(isPublicServerIP(ip), false, ip);
    }
});

test('既定のトランスポートでは非グローバルアドレスへ問い合わせない', async () => {
    const result = await traceDomain('example.com', ['127.0.0.1', '::1'], new Map());

    assert.deepEqual(result.map(log => log.status), [
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS',
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS'
    ]);
});

test('委任追跡は非グローバルな glue アドレスへ問い合わせない', async () => {
    const queriedServers = [];
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        {
            isAllowedServerIP: isTestNetAllowed,
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async (domain, serverIp) => {
                queriedServers.push(serverIp);
                if (serverIp === '192.0.2.10') {
                    return {
                        flags: 0,
                        answers: [],
                        authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                        additionals: [
                            { type: 'A', name: 'ns1.child.example.com', data: '127.0.0.1' },
                            { type: 'A', name: 'ns1.child.example.com', data: '10.0.0.2' },
                            { type: 'AAAA', name: 'ns1.child.example.com', data: '::1' }
                        ]
                    };
                }
                assert.fail(`非グローバルアドレスへ問い合わせました: ${serverIp}`);
            }
        }
    );

    assert.deepEqual(queriedServers, ['192.0.2.10']);
    assert.deepEqual(result.map(log => log.status), [
        'DELEGATED',
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS',
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS',
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS'
    ]);
    assert.deepEqual(result.slice(1).map(log => log.server), ['127.0.0.1', '10.0.0.2', '::1']);
});

test('委任追跡は 1 referral あたりの NS アドレス数を制限する', async () => {
    const glueIPs = Array.from({ length: 40 }, (_, index) => `192.0.2.${index + 100}`);
    const queriedServers = new Set();
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        {
            isAllowedServerIP: isTestNetAllowed,
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async (domain, serverIp) => {
                queriedServers.add(serverIp);
                if (serverIp === '192.0.2.10') {
                    return {
                        flags: 0,
                        answers: [],
                        authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                        additionals: glueIPs.map(ip => ({ type: 'A', name: 'ns1.child.example.com', data: ip }))
                    };
                }
                return { error: 'TIMEOUT' };
            }
        }
    );

    assert.equal(queriedServers.size, 1 + 32);
    assert.equal(result.filter(log => log.status === 'LAME_DELEGATION_TIMEOUT').length, 32);
    assert.match(result[0].addressSelectionNotes[0], /上限 \(32\) を超えた/);
});

test('DNS 問い合わせ数の上限に達すると以降の問い合わせを行わない', async () => {
    const queryBudget = { remaining: 0, exhausted: false };
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        {
            queryBudget,
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async () => assert.fail('上限到達後に問い合わせました')
        }
    );

    assert.deepEqual(result.map(log => log.status), ['QUERY_LIMIT_EXCEEDED']);
    assert.equal(queryBudget.exhausted, true);
});

test('ゾーン頂点探索は非グローバルな NS アドレスしか無い委任を辿らない', async () => {
    const queriedServers = [];
    const result = await getZoneApex('evil.example', new Map(), {
        isAllowedServerIP: isTestNetAllowed,
        resolveServerIPs: async name => name === 'a.root-servers.net' ? ['192.0.2.1'] : null,
        queryDirectlyUDP: async (qname, serverIp) => {
            queriedServers.push(serverIp);
            if (qname === 'example') {
                return {
                    flags: 0,
                    answers: [],
                    authorities: [{ type: 'NS', name: 'example', data: 'ns.example' }],
                    additionals: [
                        { type: 'A', name: 'ns.example', data: '169.254.169.254' },
                        { type: 'AAAA', name: 'ns.example', data: 'fe80::1' }
                    ]
                };
            }
            assert.fail(`想定外の問い合わせ: ${qname} (${serverIp})`);
        }
    });

    assert.deepEqual(queriedServers, ['192.0.2.1']);
    assert.equal(result.hasZoneApexLookupFailure, true);
    assert.equal(result.zoneApex, '');
    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'LAME_DELEGATION_NON_PUBLIC_ADDRESS'
    ]);
    assert.match(result.explorationLogs[0].addressSelectionNotes[0], /169\.254\.169\.254/);
});

async function withServer(callback) {
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    try {
        return await callback(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

test('トップページはセキュリティヘッダーを付与し X-Powered-By を返さない', async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/`);
        const csp = response.headers.get('content-security-policy');

        assert.equal(response.status, 200);
        assert.equal(response.headers.get('x-powered-by'), null);
        assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(response.headers.get('x-frame-options'), 'DENY');
        assert.match(csp, /default-src 'none'/);
        assert.match(csp, /script-src 'sha256-[A-Za-z0-9+/]+=*'/);
        assert.match(csp, /frame-ancestors 'none'/);
        assert.doesNotMatch(await response.text(), /\son[a-z]+="/i);
    });
});

test('API は不正な入力に対して内部情報を含まない JSON エラーを返す', async () => {
    await withServer(async baseUrl => {
        const malformed = await fetch(`${baseUrl}/api/trace`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{"domain":'
        });
        const malformedBody = await malformed.text();
        assert.equal(malformed.status, 400);
        assert.doesNotMatch(malformedBody, /at .*\.js|SyntaxError/);
        assert.equal(JSON.parse(malformedBody).success, false);

        const tooLarge = await fetch(`${baseUrl}/api/trace`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: 'a'.repeat(4096) })
        });
        assert.equal(tooLarge.status, 413);

        for (const domain of [['example.com'], { toString: 'example.com' }, 'localhost']) {
            const response = await fetch(`${baseUrl}/api/trace`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });
            assert.equal(response.status, 400, JSON.stringify(domain));
        }
    });
});
