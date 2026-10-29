import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';

import { createApp } from '../dns-delegation-check.js';

const rootIP = '8.8.8.8';
const parentIP = '1.1.1.1';
const childIP = '9.9.9.9';

function referral(zone, serverName, address) {
    return {
        flags: 0,
        answers: [],
        authorities: [{ type: 'NS', name: zone, data: serverName }],
        additionals: [{ type: 'A', name: serverName, data: address }]
    };
}

function authoritative(answers) {
    return { flags: 1024, answers, authorities: [], additionals: [] };
}

function createDnsFixture({ mismatch = false, colocated = false, cname = false } = {}) {
    const queries = [];
    const resolutions = [];
    const responses = new Map([
        [`${rootIP}|com|NS`, referral('com', 'ns.com', parentIP)],
        [`${parentIP}|example.com|NS`, colocated
            ? authoritative([{ type: 'NS', name: 'example.com', data: 'ns.com' }])
            : referral('example.com', 'ns.example.com', childIP)],
        [`${childIP}|example.com|NS`, authoritative(cname
            ? [{ type: 'CNAME', name: 'example.com', data: 'alias.example.net' }]
            : [{ type: 'NS', name: 'example.com', data: mismatch ? 'other.example.com' : 'ns.example.com' }])],
        [`${childIP}|ns.example.com|A`, authoritative([
            { type: 'A', name: 'ns.example.com', data: childIP }
        ])],
        [`${childIP}|ns.example.com|AAAA`, authoritative([])]
    ]);

    return {
        queries,
        resolutions,
        dependencies: {
            resolveServerIPs: async (name, dependencies) => {
                resolutions.push({ name, dependencies });
                assert.equal(name, 'a.root-servers.net', 'Unexpected DNS name resolution');
                return [rootIP];
            },
            queryDirectlyUDP: async (name, serverIP, cache, type, options) => {
                queries.push({ name, serverIP, cache, type, options });
                const key = `${serverIP}|${name}|${type}`;
                assert.ok(responses.has(key), `Missing DNS fixture: ${key}`);
                return responses.get(key);
            }
        }
    };
}

async function withServer(t, dependencies, callback) {
    const server = createApp(dependencies).listen(0, '127.0.0.1');
    t.after(() => new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve());
        server.closeIdleConnections();
    }));
    await once(server, 'listening');
    await callback(`http://127.0.0.1:${server.address().port}`);
}

async function requestTrace(baseUrl, domain = 'example.com') {
    const response = await fetch(`${baseUrl}/api/trace`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
    });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^application\/json\b/);
    const body = await response.json();
    assert.deepEqual(Object.keys(body).sort(), [
        'parentDelegationUnavailable', 'parentGlueInfos', 'success', 'traceLog', 'zoneApexLog'
    ]);
    assert.equal(body.success, true);
    assert.equal(typeof body.parentDelegationUnavailable, 'boolean');
    for (const key of ['parentGlueInfos', 'zoneApexLog', 'traceLog']) {
        assert.ok(Array.isArray(body[key]), key);
    }
    for (const log of [...body.zoneApexLog, ...body.traceLog]) {
        assert.equal(typeof log.server, 'string');
        assert.ok(log.parent === null || typeof log.parent === 'string');
        assert.equal(typeof log.status, 'string');
        assert.equal(typeof log.detail, 'string');
        for (const key of ['nsMatch', 'glueMatch']) {
            assert.ok(log[key] === null || (
                typeof log[key]?.success === 'boolean' && typeof log[key]?.msg === 'string'
            ), key);
        }
    }
    return body;
}

test('POST /api/trace は正常な委任を HTTP 200 と所定の JSON で返す', async t => {
    const fixture = createDnsFixture();
    await withServer(t, fixture.dependencies, async baseUrl => {
        const body = await requestTrace(baseUrl, ' HTTPS://Example.COM/ ');

        assert.equal(body.parentDelegationUnavailable, false);
        assert.deepEqual(body.zoneApexLog.map(log => log.status), [
            'FOLLOW_DELEGATION', 'FOLLOW_DELEGATION', 'ZONE_APEX_FOUND'
        ]);
        assert.deepEqual(body.traceLog.map(log => log.status), ['DELEGATED', 'SUCCESS']);
        const child = body.traceLog[1];
        assert.equal(child.server, childIP);
        assert.equal(child.serverName, 'ns.example.com');
        assert.equal(child.parent, parentIP);
        assert.equal(child.nsMatch.success, true);
        assert.equal(child.glueMatch.success, true);
        assert.deepEqual(body.parentGlueInfos, [{
            server: parentIP,
            serverName: 'ns.com',
            parentZone: 'com',
            delegatedZone: 'example.com',
            records: [{
                type: 'A', name: 'ns.example.com', data: childIP, classification: 'in-domain'
            }]
        }]);

        assert.equal(fixture.resolutions.length, 1);
        const { dependencies } = fixture.resolutions[0];
        assert.ok(dependencies.dnsResponseCache instanceof Map);
        assert.ok(dependencies.signal instanceof AbortSignal);
        assert.ok(fixture.queries.length > 0);
        assert.ok(fixture.queries.every(query =>
            query.cache === dependencies.dnsResponseCache &&
            query.options.signal === dependencies.signal &&
            !query.options.signal.aborted
        ));
        assert.deepEqual(fixture.queries.map(({ name, serverIP, type }) => [name, serverIP, type]), [
            ['com', rootIP, 'NS'],
            ['example.com', parentIP, 'NS'],
            ['example.com', childIP, 'NS'],
            ['example.com', parentIP, 'NS'],
            ['example.com', childIP, 'NS'],
            ['ns.example.com', childIP, 'A'],
            ['ns.example.com', childIP, 'AAAA']
        ]);

        const repeated = await requestTrace(baseUrl);
        assert.deepEqual(repeated, body);
        assert.equal(fixture.resolutions.length, 2);
        const nextDependencies = fixture.resolutions[1].dependencies;
        assert.notEqual(nextDependencies.dnsResponseCache, dependencies.dnsResponseCache);
        assert.notEqual(nextDependencies.signal, dependencies.signal);
    });
});

test('POST /api/trace は NS 不一致を HTTP エラーではなく検査結果として返す', async t => {
    const fixture = createDnsFixture({ mismatch: true });
    await withServer(t, fixture.dependencies, async baseUrl => {
        const body = await requestTrace(baseUrl);
        assert.equal(body.parentDelegationUnavailable, false);
        assert.deepEqual(body.traceLog.map(log => log.status), [
            'DELEGATED', 'LAME_DELEGATION_NOT_MATCH'
        ]);
        assert.equal(body.traceLog[1].nsMatch.success, false);
        assert.equal(body.traceLog[1].glueMatch.success, true);
    });
});

test('POST /api/trace は親子同居で比較不能の場合も所定の JSON で返す', async t => {
    const fixture = createDnsFixture({ colocated: true });
    await withServer(t, fixture.dependencies, async baseUrl => {
        const body = await requestTrace(baseUrl);
        assert.equal(body.parentDelegationUnavailable, true);
        assert.deepEqual(body.parentGlueInfos, []);
        assert.deepEqual(body.traceLog.map(log => log.status), ['COLOCATED_DELEGATION']);
        assert.equal(body.zoneApexLog.at(-1).status, 'ZONE_APEX_FOUND');
        assert.equal(fixture.queries.length, 2, 'Do not trace a colocated delegation');
    });
});

test('POST /api/trace は CNAME による探索終了を空の委任追跡ログとともに返す', async t => {
    const fixture = createDnsFixture({ cname: true });
    await withServer(t, fixture.dependencies, async baseUrl => {
        const body = await requestTrace(baseUrl);
        assert.equal(body.parentDelegationUnavailable, false);
        assert.equal(body.zoneApexLog.at(-1).status, 'CNAME_FOUND');
        assert.deepEqual(body.traceLog, []);
        assert.deepEqual(body.parentGlueInfos, []);
        assert.equal(fixture.queries.length, 3);
    });
});

test('POST /api/trace は内部例外の詳細を隠し、失敗後に実行枠を解放する', async t => {
    const fixture = createDnsFixture();
    const queryDirectlyUDP = fixture.dependencies.queryDirectlyUDP;
    let shouldThrow = true;
    fixture.dependencies.queryDirectlyUDP = async (...args) => {
        if (shouldThrow) throw new Error('sensitive internal details');
        return queryDirectlyUDP(...args);
    };
    const loggedErrors = t.mock.method(console, 'error', () => {});

    await withServer(t, fixture.dependencies, async baseUrl => {
        const failedResponse = await fetch(`${baseUrl}/api/trace`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: 'example.com' })
        });
        const failedBody = await failedResponse.text();

        assert.equal(failedResponse.status, 500);
        assert.match(failedResponse.headers.get('content-type'), /^application\/json\b/);
        assert.deepEqual(JSON.parse(failedBody), {
            success: false,
            error: '内部エラーが発生しました。'
        });
        assert.doesNotMatch(failedBody, /sensitive internal details|at .*\.js/);
        assert.equal(loggedErrors.mock.callCount(), 1);

        const secondFailedResponse = await fetch(`${baseUrl}/api/trace`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: 'example.com' })
        });
        await secondFailedResponse.text();
        assert.equal(secondFailedResponse.status, 500);

        shouldThrow = false;
        const recoveredBody = await requestTrace(baseUrl);
        assert.equal(recoveredBody.success, true);
    });
});
