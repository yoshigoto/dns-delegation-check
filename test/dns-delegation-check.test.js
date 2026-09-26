import assert from 'node:assert/strict';
import test from 'node:test';

import {
    getZoneApex,
    getMinimizedQnames,
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

test('最小化した問い合わせ名をルートから順に作る', () => {
    assert.deepEqual(getMinimizedQnames('www.Example.COM.'), [
        'com',
        'example.com',
        'www.example.com'
    ]);
});

test('RFC 9471 要約で in-domain glue の不足とゾーン外アドレスを示す', () => {
    const nsRecords = [
        { type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' },
        { type: 'NS', name: 'child.example.com', data: 'ns2.external.example.net' },
        { type: 'NS', name: 'child.example.com', data: 'ns3.sibling.example.com' }
    ];
    const additionals = [
        { type: 'A', name: 'ns1.child.example.com', data: '192.0.2.10' },
        { type: 'A', name: 'ns2.external.example.net', data: '192.0.2.11' },
        { type: 'A', name: 'ns3.sibling.example.com', data: '192.0.2.12' }
    ];

    const summary = summarizeRfc9471Referral(nsRecords, additionals, 'udp-truncated');

    assert.match(summary, /TCP で再取得しました/);
    assert.match(summary, /in-domain glue: \[ns1\.child\.example\.com\]/);
    assert.match(summary, /sibling glue \[ns3\.sibling\.example\.com: 192\.0\.2\.12\] は strict glue のため採用せず、名前解決を行います/);
    assert.match(summary, /RFC 9499 で Unrelated.*ns2\.external\.example\.net: 192\.0\.2\.11.*採用しません/);
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
            assert.equal(result.hasCnameOrDname, true);
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

    assert.equal(result.hasCnameOrDname, true);
    assert.equal(result.zoneApex, '');
    assert.equal(result.explorationLogs.at(-1).status, 'CNAME_FOUND');
});

test('A レコード応答では直前に委任されたゾーンを頂点として確定する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'com', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('com', 'ns.com', '192.0.2.2') },
        { qname: 'example.com', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('example.com', 'ns.example.com', '192.0.2.3') },
        {
            qname: 'host.example.com', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [{ type: 'A', name: 'host.example.com', data: '192.0.2.10' }],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('host.example.com', new Map(), dependencies);

    assert.equal(result.zoneApex, 'example.com');
    assert.equal(result.parentServerNameMap['192.0.2.2'], 'ns.com');
    assert.equal(result.hasAddressRecordWithoutDelegation, true);
    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'FOLLOW_DELEGATION',
        'ADDRESS_RECORD_FOUND',
        'ZONE_APEX_FOUND'
    ]);
});

test('委任のない権威応答でゾーン頂点探索を終了する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'com', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('com', 'ns.com', '192.0.2.2') },
        { qname: 'example.com', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('example.com', 'ns.example.com', '192.0.2.3') },
        {
            qname: 'host.example.com', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [],
                authorities: []
            }
        },
        { qname: 'host.example.com', serverIp: '192.0.2.3', qType: 'DS', value: { flags: 1024, answers: [], authorities: [] } }
    ]);

    const result = await getZoneApex('host.example.com', new Map(), dependencies);

    assert.equal(result.zoneApex, 'example.com');
    assert.equal(result.hasNoDelegationForQname, true);
    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'FOLLOW_DELEGATION',
        'AUTHORITATIVE_NO_DELEGATION',
        'NO_DELEGATION_FOR_QNAME',
        'ZONE_APEX_FOUND'
    ]);
});

test('ゾーン頂点探索は sibling glue を採用せず TLD 委任を辿れない', async () => {
    const dependencies = createZoneApexTestDependencies([
        {
            qname: 'com', serverIp: '192.0.2.1', qType: 'NS', value: {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'com', data: 'l.gtld-servers.net' }],
                additionals: [{ type: 'A', name: 'l.gtld-servers.net', data: '192.0.2.2' }]
            }
        },
        { qname: 'yodobashi.com', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('yodobashi.com', 'ns1.yodobashi.com', '192.0.2.3') },
        {
            qname: 'yodobashi.com', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [{ type: 'NS', name: 'yodobashi.com', data: 'ns1.yodobashi.com' }],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('yodobashi.com', new Map(), dependencies);

    assert.equal(result.zoneApex, '');
    assert.equal(result.explorationLogs[0].status, 'FOLLOW_DELEGATION');
    assert.deepEqual(result.explorationLogs[0].glueIPs, []);
    assert.deepEqual(result.explorationLogs[0].fallbackAddressNotes, []);
    assert.match(result.explorationLogs[0].rfc9471, /sibling glue \[l\.gtld-servers\.net: 192\.0\.2\.2\].*strict glue のため採用せず/);
    assert.equal(result.explorationLogs[1].status, 'LAME_DELEGATION_NO_NS_IP_ADDRESS');
});

test('ゾーン頂点探索は Unrelated な ADDITIONAL アドレスを採用しない', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'jp', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('jp', 'ns.jp', '192.0.2.2') },
        {
            qname: 'example.jp', serverIp: '192.0.2.2', qType: 'NS', value: {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'example.jp', data: 'ns1.example.com' }],
                additionals: [{ type: 'A', name: 'ns1.example.com', data: '192.0.2.66' }]
            }
        }
    ]);

    const result = await getZoneApex('example.jp', new Map(), dependencies);

    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'FOLLOW_DELEGATION',
        'LAME_DELEGATION_NO_NS_IP_ADDRESS'
    ]);
    assert.equal(result.zoneApex, '');
    assert.equal(result.hasZoneApexLookupFailure, true);
    assert.deepEqual(result.explorationLogs[1].glueIPs, []);
    assert.match(result.explorationLogs[1].rfc9471, /Unrelated.*192\.0\.2\.66.*採用しません/);
});

test('中間ラベルに委任がない場合でも下位ラベルの委任を探索してゾーン頂点を確定する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'jp', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('jp', 'ns.jp', '192.0.2.2') },
        {
            qname: 'co.jp', serverIp: '192.0.2.2', qType: 'NS', value: {
                flags: 1024,
                answers: [],
                authorities: []
            }
        },
        { qname: 'co.jp', serverIp: '192.0.2.2', qType: 'DS', value: { flags: 1024, answers: [], authorities: [] } },
        { qname: 'example.co.jp', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('example.co.jp', 'ns.example.co.jp', '192.0.2.3') },
        {
            qname: 'example.co.jp', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [{ type: 'NS', name: 'example.co.jp', data: 'ns.example.co.jp' }],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('example.co.jp', new Map(), dependencies);

    assert.equal(result.zoneApex, 'example.co.jp');
    assert.equal(result.hasNoDelegationForQname, false);
    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'AUTHORITATIVE_NO_DELEGATION',
        'FOLLOW_DELEGATION',
        'ZONE_APEX_FOUND'
    ]);
});

test('ホスト名入力（例: www.on-link.jp）でホストへの委任がない場合でも委任されたゾーンを頂点として確定する', async () => {
    const dependencies = createZoneApexTestDependencies([
        { qname: 'jp', serverIp: '192.0.2.1', qType: 'NS', value: referralResponse('jp', 'ns.jp', '192.0.2.2') },
        { qname: 'on-link.jp', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('on-link.jp', 'ns.on-link.jp', '192.0.2.3') },
        {
            qname: 'www.on-link.jp', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [],
                authorities: []
            }
        },
        { qname: 'www.on-link.jp', serverIp: '192.0.2.3', qType: 'DS', value: { flags: 1024, answers: [], authorities: [] } }
    ]);

    const result = await getZoneApex('www.on-link.jp', new Map(), dependencies);

    assert.equal(result.zoneApex, 'on-link.jp');
    assert.equal(result.hasNoDelegationForQname, true);
    assert.deepEqual(result.explorationLogs.map(log => log.status), [
        'FOLLOW_DELEGATION',
        'FOLLOW_DELEGATION',
        'AUTHORITATIVE_NO_DELEGATION',
        'NO_DELEGATION_FOR_QNAME',
        'ZONE_APEX_FOUND'
    ]);
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

    assert.equal(result.hasCnameOrDname, true);
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

test('親子同居の後に正規の委任が続く場合、より深いゾーンカットをゾーン頂点として確定する', async () => {
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
        { qname: 'sub.example.com', serverIp: '192.0.2.2', qType: 'NS', value: referralResponse('sub.example.com', 'ns.sub.example.com', '192.0.2.3') },
        {
            qname: 'sub.example.com', serverIp: '192.0.2.3', qType: 'NS', value: {
                flags: 1024,
                answers: [],
                authorities: []
            }
        }
    ]);

    const result = await getZoneApex('sub.example.com', new Map(), dependencies);
    const statuses = result.explorationLogs.map(log => log.status);

    assert.equal(result.zoneApex, 'sub.example.com');
    assert.equal(result.parentDelegationUnavailable, false);
    assert.ok(statuses.includes('COLOCATED_DELEGATION'));
    assert.equal(statuses.at(-1), 'ZONE_APEX_FOUND');
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

test('複数の委任先 NS は並列に問い合わせ、タイムアウト待ちを累積しない', async () => {
    const queryDelayMs = 30;
    const startedAt = Date.now();
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.10', '192.0.2.11', '192.0.2.12'],
        new Map(),
        null,
        1,
        [],
        {},
        {
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async () => {
                await new Promise(resolve => setTimeout(resolve, queryDelayMs));
                return { error: 'TIMEOUT' };
            }
        }
    );

    assert.equal(result.length, 3);
    assert.ok(Date.now() - startedAt < queryDelayMs * 2, '委任先 NS への問い合わせは並列に実行される');
    assert.deepEqual(result.map(log => log.status), [
        'LAME_DELEGATION_TIMEOUT',
        'LAME_DELEGATION_TIMEOUT',
        'LAME_DELEGATION_TIMEOUT'
    ]);
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

test('委任追跡は sibling glue を採用せず次サーバへ進まない', async () => {
    const result = await traceDomain(
        'yodobashi.com',
        ['192.0.2.1'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({
            '192.0.2.1': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'com', data: 'l.gtld-servers.net' }],
                additionals: [{ type: 'A', name: 'l.gtld-servers.net', data: '192.0.2.2' }]
            },
            '192.0.2.2': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'yodobashi.com', data: 'ns1.yodobashi.com' }],
                additionals: [{ type: 'A', name: 'ns1.yodobashi.com', data: '192.0.2.3' }]
            },
            '192.0.2.3': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'yodobashi.com', data: 'ns1.yodobashi.com' }],
                authorities: []
            }
        }, {
            'ns1.yodobashi.com': ['192.0.2.3']
        })
    );

    assert.deepEqual(result.map(log => log.status), ['DELEGATED', 'LAME_DELEGATION_NO_NS_IP_ADDRESS']);
    assert.match(result[0].rfc9471, /sibling glue \[l\.gtld-servers\.net: 192\.0\.2\.2\].*strict glue のため採用せず/);
    assert.deepEqual(result[0].fallbackAddressNotes, []);
    assert.doesNotMatch(result[0].detail, /ADDITIONAL SECTION/);
});

test('委任追跡は Unrelated な ADDITIONAL アドレスを採用しない', async () => {
    const result = await traceDomain(
        'example.jp',
        ['192.0.2.1'],
        new Map(),
        null,
        1,
        [],
        {},
        {
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async (domain, serverIp) => {
                if (serverIp === '192.0.2.1') {
                    return {
                        flags: 0,
                        answers: [],
                        authorities: [{ type: 'NS', name: 'jp', data: 'ns.jp' }],
                        additionals: [{ type: 'A', name: 'ns.jp', data: '192.0.2.2' }]
                    };
                }
                assert.equal(serverIp, '192.0.2.2', 'Unrelated な ADDITIONAL の IP に問い合わせてはいけません');
                return {
                    flags: 0,
                    answers: [],
                    authorities: [{ type: 'NS', name: 'example.jp', data: 'ns1.example.com' }],
                    additionals: [{ type: 'A', name: 'ns1.example.com', data: '192.0.2.66' }]
                };
            }
        }
    );

    assert.deepEqual(result.map(log => log.status), ['DELEGATED', 'DELEGATED', 'LAME_DELEGATION_NO_NS_IP_ADDRESS']);
    assert.match(result[1].rfc9471, /Unrelated.*192\.0\.2\.66.*採用しません/);
});

test('委任追跡はゾーン外 ADDITIONAL アドレスより NS 名の名前解決結果を優先する', async () => {
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.1'],
        new Map(),
        null,
        1,
        [],
        {},
        createTraceTestDependencies({
            '192.0.2.1': {
                flags: 0,
                answers: [],
                authorities: [{ type: 'NS', name: 'child.example.com', data: 'ns1.example.net' }],
                additionals: [{ type: 'A', name: 'ns1.example.net', data: '192.0.2.2' }]
            },
            '192.0.2.3': {
                flags: 1024,
                answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.example.net' }],
                authorities: []
            }
        }, {
            'ns1.example.net': ['192.0.2.3']
        })
    );

    assert.deepEqual(result.map(log => log.status), ['DELEGATED', 'SUCCESS']);
    assert.equal(result[1].server, '192.0.2.3');
    assert.equal(result[1].serverName, 'ns1.example.net');
    assert.deepEqual(result[0].fallbackAddressNotes, []);
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
    assert.equal(result[1].server, '192.0.2.20');
    assert.equal(result[1].serverName, 'ns1.child.example.com');
    assert.equal(result[1].nsMatch.success, true);
    assert.equal(result[1].glueMatch.success, true);
    assert.deepEqual(result[0].fallbackAddressNotes, []);
});

test('Glue 比較では子ゾーン権威サーバーから得た NS の IP を再帰的名前解決より優先する', async () => {
    const result = await traceDomain(
        'child.example.com',
        ['192.0.2.20'],
        new Map(),
        null,
        1,
        ['ns1.child.example.com'],
        { 'ns1.child.example.com': ['192.0.2.20'] },
        {
            resolveServerIPs: async () => null,
            queryDirectlyUDP: async (name, serverIp, cache, type) => {
                assert.equal(serverIp, '192.0.2.20');
                if (type === 'NS') {
                    return {
                        flags: 1024,
                        answers: [{ type: 'NS', name: 'child.example.com', data: 'ns1.child.example.com' }],
                        authorities: []
                    };
                }
                return {
                    flags: 1024,
                    answers: type === 'A'
                        ? [{ type: 'A', name, data: '192.0.2.20' }]
                        : [],
                    authorities: []
                };
            }
        }
    );

    assert.equal(result[0].status, 'SUCCESS');
    assert.equal(result[0].glueMatch.success, true);
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