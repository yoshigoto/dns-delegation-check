import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

function createElement() {
    return {
        children: [],
        className: '',
        innerHTML: '',
        textContent: '',
        classList: {
            add() {},
            remove() {}
        },
        appendChild(child) {
            this.children.push(child);
        }
    };
}

function loadBuildSummary() {
    const domainInput = createElement();
    const summaryPanel = createElement();
    const context = {
        URL,
        URLSearchParams,
        document: {
            createElement,
            getElementById(id) {
                return id === 'domain' ? domainInput : summaryPanel;
            }
        }
    };
    const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

    vm.runInNewContext(script, context);
    return {
        buildSummary: context.buildSummary,
        summaryPanel
    };
}

function loadPageWithSearch(search = '', fetchImpl) {
    const domainInput = createElement();
    const summaryPanel = createElement();
    const resultContainer = createElement();
    const context = {
        URL,
        URLSearchParams,
        AbortController,
        setTimeout,
        clearTimeout,
        fetch: fetchImpl || (async () => ({
            json: async () => ({
                success: true,
                zoneApexLog: [{ status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' }],
                traceLog: [{ status: 'SUCCESS', detail: '委任は正常です。' }]
            })
        })),
        window: { location: { search } },
        alert() {},
        document: {
            createElement,
            getElementById(id) {
                if (id === 'domain') return domainInput;
                if (id === 'summary-panel') return summaryPanel;
                if (id === 'result-container') return resultContainer;
                return null;
            }
        }
    };
    const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

    vm.runInNewContext(script, context);
    return {
        domainInput,
        summaryPanel,
        resultContainer,
        startTrace: context.startTrace,
        renderLogTree: context.renderLogTree,
        renderGlueInfo: context.renderGlueInfo,
        buildDualLogView: context.buildDualLogView
    };
}

function renderVerdict(logData, parentDelegationUnavailable = false, delegationLogData = logData) {
    const { buildSummary, summaryPanel } = loadBuildSummary();
    buildSummary(logData, parentDelegationUnavailable, delegationLogData);
    return summaryPanel.children[0].textContent;
}

function getElementText(element) {
    return [element.textContent, ...element.children.map(getElementText)].join('\n');
}

test('グルー情報の箱は委任追跡ログの下に表示し、親サーバーごとの応答を表示する', () => {
    const { buildDualLogView } = loadPageWithSearch();
    const target = createElement();
    const info = {
        server: '192.0.2.1', serverName: 'ns.example.com', parentZone: 'example.com',
        delegatedZone: 'child.example.com',
        records: [
            { name: 'ns.child.example.com', ttl: 3600, class: 'IN', type: 'A', data: '192.0.2.10', classification: 'in-domain' },
            { name: 'ns.sibling.example.com', ttl: 60, type: 'AAAA', data: '2001:db8::1', classification: 'sibling domain' },
            { name: 'ns.example.net', ttl: 60, type: 'A', data: '192.0.2.11', classification: 'unrelated' },
            { name: '<img src=x onerror=alert(1)>', type: 'TXT', data: { value: 'test' }, classification: null }
        ]
    };
    buildDualLogView([], [
        { server: '192.0.2.1', parent: null, status: 'DELEGATED', glueInfo: info },
        { server: '192.0.2.2', parent: null, status: 'DELEGATED', glueInfo: { ...info, server: 'SECOND_SERVER', records: [] } }
    ], target);
    const panels = target.children[0].children;
    assert.deepEqual(panels.map(panel => panel.children[0].textContent),
        ['ゾーン頂点探索ログ', '委任追跡ログ', 'グルー情報']);
    const body = panels[2].children[1];
    const text = getElementText(body);
    for (const expected of ['ns.example.com (192.0.2.1)', 'child.example.com', '3600', 'IN', 'AAAA',
        '192.0.2.10', '2001:db8::1', 'in-domain', 'sibling domain', 'unrelated', '分類対象外', '{"value":"test"}']) {
        assert.ok(text.includes(expected), expected);
    }
    assert.ok(text.includes('SECOND_SERVER'));
    const sections = body.children.filter(element => element.className === 'glue-server');
    assert.equal(sections.length, 2);
    assert.match(getElementText(sections[1]), /ADDITIONAL SECTION は空/);
    const table = sections[0].children.find(element => element.className === 'glue-table');
    const unsafeNameCell = table.children[1].children.find(row =>
        row.children[0].textContent === '<img src=x onerror=alert(1)>'
    ).children[0];
    assert.equal(unsafeNameCell.textContent, '<img src=x onerror=alert(1)>');
    assert.equal(unsafeNameCell.innerHTML, '');
});

test('グルー情報は名前を最優先、内容を次の優先度で自然順にソートし、元の応答を変更しない', () => {
    const { renderGlueInfo } = loadPageWithSearch();
    const target = createElement();
    const records = [
        { name: 'ns10.example.com', type: 'A', data: '192.0.2.1' },
        { name: 'NS2.Example.COM.', type: 'A', data: '192.0.2.10' },
        { name: 'ns1.example.com', type: 'AAAA', data: '2001:db8::10' },
        { name: 'ns2.example.com', type: 'A', data: '192.0.2.2' },
        { name: 'ns1.example.com', type: 'AAAA', data: '2001:db8::2' },
        { name: 'ns2.example.com.', type: 'A', data: '192.0.2.2', ttl: 60 },
        { name: 'txt.example.com', type: 'TXT', data: { value: 'b' } },
        { name: 'txt.example.com', type: 'TXT', data: { value: 'a' } }
    ];
    const original = structuredClone(records);
    renderGlueInfo([], target, false, [], [{ server: '192.0.2.1', parentZone: 'com', records }]);
    const section = target.children.find(element => element.className === 'glue-server');
    const table = section.children.find(element => element.className === 'glue-table');
    const rows = table.children[1].children;
    assert.deepEqual(rows.map(row => [row.children[0].textContent, row.children[4].textContent]), [
        ['ns1.example.com', '2001:db8::2'],
        ['ns1.example.com', '2001:db8::10'],
        ['ns2.example.com', '192.0.2.2'],
        ['ns2.example.com.', '192.0.2.2'],
        ['NS2.Example.COM.', '192.0.2.10'],
        ['ns10.example.com', '192.0.2.1'],
        ['txt.example.com', '{"value":"a"}'],
        ['txt.example.com', '{"value":"b"}']
    ]);
    assert.deepEqual(records, original);
});

test('空の ADDITIONAL と取得不能を区別し、後続サーバーのレコードも表示する', () => {
    const { renderGlueInfo } = loadPageWithSearch();
    const target = createElement();
    renderGlueInfo([
        { glueInfo: { server: '192.0.2.1', parentZone: 'com', records: [] } },
        { glueInfo: { server: 'SECOND_SERVER', parentZone: 'com', records: [{ type: 'A', data: '192.0.2.99' }] } }
    ], target);
    assert.match(getElementText(target), /ADDITIONAL SECTION は空です（OPT Pseudo Section は除外）/);
    assert.ok(getElementText(target).includes('SECOND_SERVER'));
    assert.ok(getElementText(target).includes('192.0.2.99'));
    const unavailable = createElement();
    renderGlueInfo([], unavailable);
    assert.match(getElementText(unavailable), /応答を取得できない/);
    assert.ok(!getElementText(unavailable).includes('空です'));
    const colocated = createElement();
    renderGlueInfo([], colocated, true);
    assert.match(getElementText(colocated), /親子ゾーンが同じ権威サーバー/);
});

test('API のサーバー別グルー情報を優先し、通信失敗を空と誤表示しない', async () => {
    const infos = [
        { server: 'FIRST', parentZone: 'com', records: [] },
        { server: '2001:db8::2', serverName: 'ns2.com', parentZone: 'com', records: null, error: 'TIMEOUT', detail: 'test error' },
        { server: 'THIRD', parentZone: 'com', records: [{ name: 'ns.example.net', type: 'A', data: '192.0.2.99', classification: 'unrelated' }] }
    ];
    const { domainInput, resultContainer, startTrace } = loadPageWithSearch('', async () => ({
        json: async () => ({
            success: true,
            zoneApexLog: [{ status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' }],
            traceLog: [{ server: 'OLD_SERVER', parent: null, status: 'DELEGATED', glueInfo: { server: 'OLD_SERVER', records: [] } }],
            parentGlueInfos: infos
        })
    }));
    domainInput.value = 'example.com';
    await startTrace();
    const body = resultContainer.children[0].children[2].children[1];
    const sections = body.children.filter(element => element.className === 'glue-server');
    assert.equal(sections.length, 3);
    assert.match(getElementText(sections[0]), /FIRST[\s\S]*空です/);
    assert.match(getElementText(sections[1]), /ns2\.com \(2001:db8::2\)[\s\S]*TIMEOUT - test error/);
    assert.ok(!getElementText(sections[1]).includes('空です'));
    assert.match(getElementText(sections[2]), /THIRD[\s\S]*192\.0\.2\.99[\s\S]*unrelated/);
    assert.ok(!getElementText(body).includes('OLD_SERVER'));
    assert.ok(!getElementText(body).includes('最初に取得'));
});

test('NS 名前解決失敗で追跡できなくても探索中に取得した親のグルー情報を表示する', () => {
    const { renderGlueInfo } = loadPageWithSearch();
    const target = createElement();
    renderGlueInfo([], target, false, [
        { glueInfo: { server: 'OLD_SERVER', parentZone: '.', records: [] } },
        { glueInfo: { server: '192.0.2.1', parentZone: 'com', records: [] } },
        { status: 'LAME_DELEGATION_NO_NS_IP_ADDRESS' }
    ]);
    assert.match(getElementText(target), /192\.0\.2\.1/);
    assert.ok(!getElementText(target).includes('OLD_SERVER'));
    assert.match(getElementText(target), /ADDITIONAL SECTION は空/);
});

test('domain クエリがあると自動で解析を開始する', async () => {
    let fetchCalled = false;
    let fetchResolved;
    const fetchPromise = new Promise(resolve => {
        fetchResolved = resolve;
    });

    loadPageWithSearch('?domain=example.com', async (url, options) => {
        fetchCalled = true;
        assert.equal(url, './api/trace');
        assert.equal(JSON.parse(options.body).domain, 'example.com');
        fetchResolved();
        return {
            json: async () => ({
                success: true,
                zoneApexLog: [{ status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' }],
                traceLog: [{ status: 'SUCCESS', detail: '委任は正常です。' }]
            })
        };
    });

    await fetchPromise;
    assert.equal(fetchCalled, true);
});

test('ADDITIONAL の IP 採用を委任ログの専用ボックスにだけ表示する', () => {
    const { renderLogTree } = loadPageWithSearch();
    const target = createElement();
    renderLogTree([
        {
            server: '192.0.2.1', parent: null, status: 'DELEGATED',
            detail: 'AUTHORITY SECTION に NS レコード。',
            rfc9471: 'UDP 応答は TC=0 でした。',
            fallbackAddressNotes: ['ns.example.net: [192.0.2.2]']
        },
        {
            server: '192.0.2.3', parent: null, status: 'DELEGATED',
            detail: 'AUTHORITY SECTION に NS レコード。',
            rfc9471: 'RFC 9499 で Unrelated と分類されるアドレスは採用しません。',
            fallbackAddressNotes: []
        }
    ], target);

    const elements = [];
    function visit(element) {
        elements.push(element);
        element.children.forEach(visit);
    }
    visit(target);

    const boxes = elements.filter(element => element.className === 'fallback-address-box');
    assert.equal(boxes.length, 1);
    assert.match(boxes[0].innerText, /IP アドレスの採用元:\rNS 名の名前解決に失敗したため、親の ADDITIONAL SECTION から採用しました。\rns\.example\.net: \[192\.0\.2\.2\]/);
    assert.equal(elements.filter(element => element.className === 'rfc9471-box match-success').length, 1);
    assert.equal(elements.filter(element => element.className === 'rfc9471-box match-fail').length, 1);
    assert.match(elements.find(element => element.className === 'rfc9471-box match-fail').innerText, /RFC 9471 \/ RFC 9499 確認結果/);
    assert.ok(elements.filter(element => element.className === 'server-detail').every(element => !element.textContent.includes('ADDITIONAL SECTION')));
});

test('verdictがゾーン頂点探索と委任追跡の結果を概要表示する', () => {
    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'SUCCESS', detail: '委任は正常です。' }
    ]), '✅  正常: 正しく委任されています');

    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'LAME_DELEGATION_NO_AUTHORITY_NS', detail: '委任情報が欠落しています。' }
    ]), '⚠️  異常検出: 委任に不整合があります');

    assert.equal(renderVerdict([
        { status: 'CNAME_FOUND', detail: '入力名は CNAME です。' }
    ]), '⚠️  検査対象外: 入力名は CNAME (別名) なので、ゾーン名を指定してください');

    assert.equal(renderVerdict([
        { status: 'LAME_DELEGATION_NO_NS_IP_ADDRESS', detail: '委任先 NS の IP アドレスを取得できず、ゾーン頂点を確認できません。' }
    ]), '⚠️  要確認: ゾーン頂点を確定できませんでした');

    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'NETWORK_ERROR', detail: '通信エラーです。' }
    ]), '⚠️  要確認: 通信エラーにより委任状態を確認できません');

    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'NETWORK_ERROR', detail: 'ゾーン頂点探索中の通信エラーです。' },
        { status: 'SUCCESS', detail: '委任は正常です。' }
    ], false, [
        { status: 'SUCCESS', detail: '委任は正常です。' }
    ]), '✅  正常: 正しく委任されています');

    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'COLOCATED_DELEGATION', detail: '親子同居です。' }
    ], true), '⚠️  検査対象外: 親子ゾーンが同じ権威サーバーのため、親子 NS 情報を比較しません');
});