import assert from 'node:assert/strict';
import test from 'node:test';

import {
    getZoneApex,
    getMinimizedQnames,
    hasParentChildRelationship,
    isInBailiwickGlue,
    isIPv6,
    normalizeDnsName,
    normalizeUserDomain,
    summarizeRfc9471Referral,
    traceDomain
} from '../dns-delegation-check.js';

function createZoneApexTestDependencies(responses) {
    return {
        resolveServerIPs: async (name) => name === 'a.root-servers.net' ? ['192.0.2.1'] : [],
        queryDirectlyUDP: async (qname, serverIp, cache, qType) => {
            const response = responses.find(item => item.qname === qname && item.serverIp === serverIp && item.qType === qType);
            assert.ok(response, `モック DNS 応答がありません: ${qType} ${qname} (${serverIp})`);
            return response.value;
        }
    };
}

function referralResponse(zone, nsName, nsIp) {
    return {
        flags: 0,
        answers: [],
        authorities: [{ type: 'NS', name: zone, data: nsName }],
        additionals: [{ type: 'A', name: nsName, data: nsIp }]
    };
}

function createTraceTestDependencies(responseByServer, resolvedIPs = {}) {
    return {
        resolveServerIPs: async (name) => resolvedIPs[name] || null,
        queryDirectlyUDP: async (domain, serverIp) => {
            const response = responseByServer[serverIp];
            assert.ok(response, `モック DNS 応答がありません: ${domain} (${serverIp})`);
            return response;
        }
    };
}

test('ドメイン入力を正規化し、不正な値を拒否する', () => {
    assert.equal(normalizeUserDomain(' HTTPS://Example.COM/ '), 'example.com');
    assert.equal(normalizeUserDomain('a.example.com.'), 'a.example.com');
    assert.equal(normalizeUserDomain('example.com/path'), '');
    assert.equal(normalizeUserDomain('localhost'), '');
    assert.equal(normalizeUserDomain('bad_domain.example'), '');
    assert.equal(normalizeUserDomain(''), '');
});

test('DNS 名を小文字化し、末尾ドットを除去する', () => {
    assert.equal(normalizeDnsName(' NS1.Example.COM. '), 'ns1.example.com');
    assert.equal(normalizeDnsName(null), '');
});

test('親子関係は同一ゾーンとサブドメインだけを一致させる', () => {
    assert.equal(hasParentChildRelationship('www.example.com', 'example.com'), true);
    assert.equal(hasParentChildRelationship('example.com.', 'example.com'), true);
    assert.equal(hasParentChildRelationship('example.com', 'ample.com'), false);
    assert.equal(hasParentChildRelationship('example.net', 'example.com'), false);
});

test('最小化した問い合わせ名をルートから順に作る', () => {
    assert.deepEqual(getMinimizedQnames('www.Example.COM.'), [
        'com',
        'example.com',
        'www.example.com'
    ]);
});

test('IPv4 と IPv6 を識別する', () => {
    assert.equal(isIPv6('2001:db8::53'), true);
    assert.equal(isIPv6('192.0.2.53'), false);
});

test('in-domain glue だけを採用する', () => {
    const nsNames = ['ns1.child.example.com', 'ns2.external.example.net'];
    assert.equal(isInBailiwickGlue({ type: 'A', name: 'ns1.child.example.com' }, nsNames, 'child.example.com'), true);
    assert.equal(isInBailiwickGlue({ type: 'AAAA', name: 'ns2.external.example.net' }, nsNames, 'child.example.com'), false);
    assert.equal(isInBailiwickGlue({ type: 'TXT', name: 'ns1.child.example.com' }, nsNames, 'child.example.com'), false);
});

test('RFC 9471 要約で in-domain glue の不足とゾーン外アドレスを示す', () => {
    const nsRecords = [
        { type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' },
        { type: 'NS', name: 'child.example.com', data: 'ns2.external.example.net' }
    ];
    const additionals = [
        { type: 'A', name: 'ns1.child.example.com', data: '192.0.2.10' },
        { type: 'A', name: 'ns2.external.example.net', data: '192.0.2.11' }
    ];

    const summary = summarizeRfc9471Referral(nsRecords, additionals, 'udp-truncated');

    assert.match(summary, /TCP で再取得しました/);
    assert.match(summary, /in-domain glue: \[ns1\.child\.example\.com\]/);
    assert.match(summary, /ゾーン外 NS の追加アドレス: ns2\.external\.example\.net/);
});

test('ゾーン頂点探索は CNAME と DNAME で終了ログを記録する', async (t) => {
    for (const record of [
        { type: 'CNAME', data: 'target.example.net', status: 'CNAME_FOUND' },
        { type: 'DNAME', data: 'target.example.net', status: 'DNAME_FOUND' }
    ]) {
        await t.test(record.type, async () => {
            const dependencies = createZoneApexTestDependencies([
                { qname: 'com', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('com', 'ns.com', '192.0.2.2') },
                { qname: 'example.com', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('example.com', 'ns.example.com', '192.0.2.3') },
                {
                    qname: 'alias.example.com', serverIp: '192.0.2.3', qType: 'NS', value: {
                        flags: 1024,
                        answers: [{ type: record.type, name: 'alias.example.com', data: record.data }],
                        authorities: []
                    }
                }
            ]);

            const result = await getZoneApex('alias.example.com', new Map(), dependencies);
            assert.equal(result.cdName, true);
            assert.equal(result.zoneApex, '');
            assert.deepEqual(result.explorationLogs.map(log => log.status), [
                'FOLLOW_DELEGATION',
                'FOLLOW_DELEGATION',
                record.status
            ]);
            assert.equal(result.explorationLogs.at(-1).parentLogId, null);
        });
    }
});

test('非権威応答の CNAME でもゾーン頂点探索を終了する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'jp', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('jp', 'ns.jp', '192.0.2.2') },
        { qname: 'co.jp', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('co.jp', 'ns.co.jp', '192.0.2.3') },
        { qname: 'tv-asahi.co.jp', serverIp: '192.0.2.3', qType: 'NS', value: referralResponse('tv-asahi.co.jp', 'ns.tv-asahi.co.jp', '192.0.2.4') },
        {
            qname: 'news.tv-asahi.co.jp', serverIp: '192.0.2.4', qType: 'NS', value: {
                flags: 0,
                answers: [{ type: 'CNAME', name: 'news.tv-asahi.co.jp', data: 'n.sni.global.fastly.net' }],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('news.tv-asahi.co.jp', new Map(), dependencies);

    assert.equal(result.cdName, true);
    assert.equal(result.zoneApex, '');
    assert.equal(result.explorationLogs.at(-1).status, 'CNAME_FOUND');
});

test('入力名への最終委任先にある CNAME を検出する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'jp', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('jp', 'ns.jp', '192.0.2.2') },
        { qname: 'co.jp', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('co.jp', 'ns.co.jp', '192.0.2.3') },
        { qname: 'tv-asahi.co.jp', serverIp: '192.0.2.3', qType: 'NS', value: referralResponse('tv-asahi.co.jp', 'ns.d-53.tv-asahi.co.jp', '192.0.2.4') },
        { qname: 'news.tv-asahi.co.jp', serverIp: '192.0.2.4', qType: 'NS', value: referralResponse('news.tv-asahi.co.jp', 'ns.aws.news.tv-asahi.co.jp', '192.0.2.5') },
        {
            qname: 'news.tv-asahi.co.jp', serverIp: '192.0.2.5', qType: 'NS', value: {
                flags: 1024,
                answers: [{ type: 'CNAME', name: 'news.tv-asahi.co.jp', data: 'n.sni.global.fastly.net' }],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('news.tv-asahi.co.jp', new Map(), dependencies);

    assert.equal(result.cdName, true);
    assert.equal(result.zoneApex, '');
    assert.equal(result.explorationLogs.at(-1).status, 'CNAME_FOUND');
    assert.equal(result.explorationLogs.at(-1).parentLogId, 'zone-apex-3');
});

test('親子同居のゾーン頂点探索ログを親子階層で保持する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'com', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('com', 'ns.com', '192.0.2.2') },
        {
            qname: 'example.com', serverIp: '192.0.2.2', qType: 'NS', value: {
                flags: 1024,
                answers: [{ type: 'NS', name: 'example.com', data: 'ns.com' }],
                authorities: []
            }
        },
        { qname: 'example.com', serverIp: '192.0.2.2', qType: 'DS', value: { flags: 1024, answers: [], authorities: [] } },
        {
            qname: 'www.example.com', serverIp: '192.0.2.2', qType: 'NS', value: {
                flags: 1024,
                answers: [],
                authorities: []
            }
        },
        { qname: 'www.example.com', serverIp: '192.0.2.2', qType: 'DS', value: { flags: 1024, answers: [], authorities: [] } }
    ]);

    const result = await getZoneApex('www.example.com', new Map(), dependencies);
    const logs = result.explorationLogs;
    const colocated = logs.find(log => log.status === 'COLOCATED_DELEGATION');
    const apex = logs.find(log => log.status === 'ZONE_APEX_FOUND');

    assert.equal(result.zoneApex, 'example.com');
    assert.equal(result.parentDelegationUnavailable, true);
    assert.ok(colocated);
    assert.ok(apex);
    assert.equal(apex.parentLogId, colocated.id);
    assert.equal(apex.parent, 'ns.com');
});

test('委任追跡の基本ステータスを判定する', async () => {
    const matching = await traceDomain(
        'child.example.com',
        ['192.0.2.20'],
        new Map(),
        null,
        1,
        ['ns1.child.example.com'],
        {},
        createTraceTestDependencies({
            '192.0.2.20': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                authorities: []
            }
        })
    );
    assert.equal(matching[0].status, 'SUCCESS');
    assert.equal(matching[0].nsMatch.success, true);

    const mismatch = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        ['ns1.child.example.com'],
        {},
        createTraceTestDependencies({
            '192.0.2.10': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns2.child.example.com' }],
                authorities: []
            }
        })
    );
    assert.equal(mismatch[0].status, 'LAME_DELEGATION_NOT_MATCH');
    assert.equal(mismatch[0].nsMatch.success, false);
});

test('委任追跡のエラー・空応答・最大深度を記録する', async () => {
    const timeout = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({ '192.0.2.10': { error: 'TIMEOUT' } })
    );
    assert.equal(timeout[0].status, 'LAME_DELEGATION_TIMEOUT');

    const noZone = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({ '192.0.2.10': { flags: 1024, answers: [], authorities: [] } })
    );
    assert.equal(noZone[0].status, 'LAME_DELEGATION_NO_ZONE');

    const networkError = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({ '192.0.2.10': { error: 'SOCKET_ERROR', detail: 'connection refused' } })
    );
    assert.equal(networkError[0].status, 'NETWORK_ERROR');

    const maxDepth = await traceDomain('child.example.com', [], new Map(), null, 11);
    assert.equal(maxDepth[0].status, 'LAME_DELEGATION_MAX_DEPTH');
});

test('委任先の IP がない場合は追跡不能として記録する', async () => {
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({
            '192.0.2.10': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                additionals: []
            }
        })
    );

    assert.deepEqual(result.map(log => log.status), [
        'DELEGATED',
        'LAME_DELEGATION_NO_NS_IP_ADDRESS'
    ]);
});

test('委任先の glue と権威 NS が一致すれば SUCCESS になる', async () => {
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({
            '192.0.2.10': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                additionals: [{ type: 'A', name: 'ns1.child.example.com', data: '192.0.2.20' }]
            },
            '192.0.2.20': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                authorities: []
            }
        }, {
            'ns1.child.example.com': ['192.0.2.20']
        })
    );

    assert.deepEqual(result.map(log => log.status), ['DELEGATED', 'SUCCESS']);
    assert.equal(result[1].nsMatch.success, true);
    assert.equal(result[1].glueMatch.success, true);
});

test('委任先の IP 不在と Glue の IP 不一致を検出する', async () => {
    const noChildIP = await traceDomain(
        'child.example.com',
        ['192.0.2.20'],
        new Map(),
        null,
        1,
        [],
        { 'ns1.child.example.com': ['192.0.2.20'] },
        createTraceTestDependencies({
            '192.0.2.20': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                authorities: []
            }
        }, { 'ns1.child.example.com': null })
    );
    assert.equal(noChildIP[0].status, 'LAME_DELEGATION_NO_IP_ADDRESS');
    assert.equal(noChildIP[0].glueMatch.success, false);

    const glueMismatch = await traceDomain(
        'child.example.com',
        ['192.0.2.10'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({
            '192.0.2.10': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                additionals: [{ type: 'A', name: 'ns1.child.example.com', data: '192.0.2.20' }]
            },
            '192.0.2.20': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                authorities: []
            }
        }, {
            'ns1.child.example.com': ['192.0.2.21']
        })
    );
    assert.equal(glueMismatch[1].status, 'LAME_DELEGATION_NOT_MATCH');
    assert.equal(glueMismatch[1].glueMatch.success, false);
});