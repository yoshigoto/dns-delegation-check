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
        renderLogTree: context.renderLogTree
    };
}

function renderVerdict(logData, parentDelegationUnavailable = false, delegationLogData = logData) {
    const { buildSummary, summaryPanel } = loadBuildSummary();
    buildSummary(logData, parentDelegationUnavailable, delegationLogData);
    return summaryPanel.children[0].textContent;
}

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