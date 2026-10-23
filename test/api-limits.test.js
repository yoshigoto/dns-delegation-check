import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import test from 'node:test';

import { createApp } from '../dns-delegation-check.js';

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

function createDnsFixture(phase = 'query') {
    const started = [];
    const waiters = [];
    const pending = new Set();
    const parentQueries = new WeakMap();
    let holding = true;
    let resolutionCount = 0;

    function hold(signal, value) {
        if (!holding) return Promise.resolve(value);
        const result = deferred();
        const aborted = deferred();
        const entry = {
            signal,
            aborted: aborted.promise,
            finish() {
                signal.removeEventListener('abort', onAbort);
                pending.delete(entry);
                result.resolve(value);
            }
        };
        function onAbort() {
            signal.removeEventListener('abort', onAbort);
            pending.delete(entry);
            result.resolve(Array.isArray(value) ? [] : { error: 'ABORTED' });
            aborted.resolve();
        }
        signal.addEventListener('abort', onAbort, { once: true });
        pending.add(entry);
        if (waiters.length) waiters.shift()(entry);
        else started.push(entry);
        return result.promise;
    }

    function referral(zone, name, ip) {
        return {
            flags: 0,
            answers: [],
            authorities: [{ type: 'NS', name: zone, data: name }],
            additionals: [{ type: 'A', name, data: ip }]
        };
    }

    return {
        get resolutionCount() { return resolutionCount; },
        get pendingCount() { return pending.size; },
        nextStarted() {
            if (started.length) return Promise.resolve(started.shift());
            return new Promise(resolve => waiters.push(resolve));
        },
        completeAll() {
            holding = false;
            for (const entry of pending) entry.finish();
        },
        dependencies: {
            resolveServerIPs: async (name, { signal }) => {
                resolutionCount++;
                assert.equal(name, 'a.root-servers.net');
                if (signal.aborted) return [];
                return phase === 'resolver' ? hold(signal, ['8.8.8.8']) : ['8.8.8.8'];
            },
            queryDirectlyUDP: async (name, ip, cache, type, { signal }) => {
                if (signal.aborted) return { error: 'ABORTED' };
                if (ip === '8.8.8.8' && name === 'com' && type === 'NS') {
                    const response = referral('com', 'ns.com', '1.1.1.1');
                    return phase === 'query' ? hold(signal, response) : response;
                }
                if (ip === '1.1.1.1' && name === 'example.com' && type === 'NS') {
                    const count = (parentQueries.get(cache) || 0) + 1;
                    parentQueries.set(cache, count);
                    const response = referral('example.com', 'ns.example.com', '9.9.9.9');
                    return phase === 'trace' && count === 2 ? hold(signal, response) : response;
                }
                if (ip === '9.9.9.9') {
                    if (name === 'example.com' && type === 'NS') {
                        return { flags: 1024, answers: [{ type: 'NS', name, data: 'ns.example.com' }] };
                    }
                    if (name === 'ns.example.com' && ['A', 'AAAA'].includes(type)) {
                        return {
                            flags: 1024,
                            answers: type === 'A' ? [{ type, name, data: ip }] : []
                        };
                    }
                }
                assert.fail(`Unexpected DNS query: ${type} ${name} (${ip})`);
            }
        }
    };
}

async function createHarness(t, phase) {
    const fixture = createDnsFixture(phase);
    const server = createApp(fixture.dependencies).listen(0, '127.0.0.1');
    const requests = new Set();
    t.after(async () => {
        fixture.completeAll();
        for (const request of requests) request.destroy();
        server.closeAllConnections();
        await new Promise((resolve, reject) => {
            server.close(error => error ? reject(error) : resolve());
        });
    });
    await once(server, 'listening');
    const url = `http://127.0.0.1:${server.address().port}/api/trace`;

    function start(client) {
        const request = http.request(url, {
            method: 'POST',
            agent: false,
            headers: {
                'Content-Type': 'application/json',
                'X-Forwarded-For': client
            }
        });
        requests.add(request);
        request.once('close', () => requests.delete(request));
        const result = new Promise((resolve, reject) => {
            request.once('error', reject);
            request.once('response', response => {
                response.setEncoding('utf8');
                let body = '';
                response.on('data', chunk => { body += chunk; });
                response.once('error', reject);
                response.once('end', () => resolve({
                    status: response.statusCode,
                    headers: response.headers,
                    body: JSON.parse(body)
                }));
            });
        });
        // 切断やテスト失敗による後片付けより先に、拒否ハンドラーを登録する。
        const outcome = result.then(
            response => ({ response }),
            error => ({ error })
        );
        request.end(JSON.stringify({ domain: 'example.com' }));
        return { request, result, outcome };
    }

    async function startHeld(client) {
        const call = start(client);
        const entry = await fixture.nextStarted();
        return { ...call, entry };
    }

    return { fixture, start, startHeld };
}

function assertRejected(response, status, retryAfter) {
    assert.equal(response.status, status);
    assert.match(response.headers['content-type'], /^application\/json\b/);
    assert.equal(response.headers['retry-after'], String(retryAfter));
    assert.deepEqual(Object.keys(response.body).sort(), ['error', 'success']);
    assert.equal(response.body.success, false);
    assert.equal(typeof response.body.error, 'string');
    assert.ok(response.body.error.length > 0);
}

async function finish(call) {
    call.entry.finish();
    const response = await call.result;
    assert.equal(response.status, 200);
    assert.equal(response.body.success, true);
    assert.equal(call.entry.signal.aborted, false, 'Normal completion must not abort DNS');
}

test('API はクライアント別に毎分10件まで許可し、60秒の境界で再び受け付ける', { timeout: 10000 }, async t => {
    const { fixture, start } = await createHarness(t);
    fixture.completeAll();
    let now = Date.now();
    t.mock.method(Date, 'now', () => now);

    for (let index = 0; index < 10; index++) {
        const response = await start('198.51.100.10').result;
        assert.equal(response.status, 200, `Request ${index + 1}`);
        assert.equal(response.body.success, true);
    }
    assert.equal(fixture.resolutionCount, 10);
    assertRejected(await start('198.51.100.10').result, 429, 60);
    assert.equal(fixture.resolutionCount, 10, 'Rate-limited requests must not start DNS');

    assert.equal((await start('198.51.100.11').result).status, 200);
    now += 59999;
    assertRejected(await start('198.51.100.10').result, 429, 1);
    now++;
    assert.equal((await start('198.51.100.10').result).status, 200);
    assert.equal(fixture.resolutionCount, 12);
});

test('API は同じクライアントの3件目を拒否し、完了後に実行枠を再利用できる', { timeout: 10000 }, async t => {
    const { fixture, start, startHeld } = await createHarness(t);
    const first = await startHeld('198.51.100.20');
    const second = await startHeld('198.51.100.20');
    for (let index = 0; index < 10; index++) {
        assertRejected(await start('198.51.100.20').result, 503, 10);
    }
    assert.equal(fixture.resolutionCount, 2);

    const other = await startHeld('198.51.100.21');
    await finish(first);
    const replacement = await startHeld('198.51.100.20');
    assertRejected(await start('198.51.100.20').result, 503, 10);
    assert.equal(fixture.resolutionCount, 4);
    await Promise.all([finish(second), finish(other), finish(replacement)]);
});

test('API は全体で8件まで許可し、完了後に全体の実行枠を再利用できる', { timeout: 10000 }, async t => {
    const { fixture, start, startHeld } = await createHarness(t);
    const calls = [];
    for (let index = 0; index < 8; index++) {
        calls.push(await startHeld(`198.51.100.${30 + index}`));
    }
    assert.equal(fixture.pendingCount, 8);
    assertRejected(await start('198.51.100.38').result, 503, 10);
    assert.equal(fixture.resolutionCount, 8);

    await finish(calls.shift());
    const replacement = await startHeld('198.51.100.38');
    assertRejected(await start('198.51.100.39').result, 503, 10);
    assert.equal(fixture.resolutionCount, 9);
    await Promise.all([...calls, replacement].map(finish));
});

for (const [index, phase] of ['resolver', 'query', 'trace'].entries()) {
    test(`クライアント切断は ${phase} 処理を中断し、クライアント別・全体の実行枠を解放する`, { timeout: 10000 }, async t => {
        const { fixture, start, startHeld } = await createHarness(t, phase);
        const client = `203.0.113.${index * 10 + 1}`;
        const disconnected = await startHeld(client);
        const remaining = [await startHeld(client)];
        for (let offset = 2; offset < 8; offset++) {
            remaining.push(await startHeld(`203.0.113.${index * 10 + offset}`));
        }
        assertRejected(await start(client).result, 503, 10);
        assert.equal(fixture.resolutionCount, 8);
        disconnected.request.destroy();
        await disconnected.entry.aborted;
        const outcome = await disconnected.outcome;
        assert.equal(outcome.error?.code, 'ECONNRESET');
        assert.equal(disconnected.entry.signal.aborted, true);

        const replacement = await startHeld(client);
        assert.equal(fixture.pendingCount, 8);
        assert.equal(fixture.resolutionCount, 9);
        assert.ok(remaining.every(call => !call.entry.signal.aborted));
        assertRejected(await start(client).result, 503, 10);
        await Promise.all([...remaining, replacement].map(finish));
    });
}
