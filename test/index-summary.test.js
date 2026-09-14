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

function renderVerdict(logData, parentDelegationUnavailable = false) {
    const { buildSummary, summaryPanel } = loadBuildSummary();
    buildSummary(logData, parentDelegationUnavailable);
    return summaryPanel.children[0].textContent;
}

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
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'NETWORK_ERROR', detail: '通信エラーです。' }
    ]), '⚠️  要確認: 通信エラーにより委任状態を確認できません');

    assert.equal(renderVerdict([
        { status: 'ZONE_APEX_FOUND', detail: 'ゾーン頂点を確定: example.com。' },
        { status: 'COLOCATED_DELEGATION', detail: '親子同居です。' }
    ], true), '⚠️  検査対象外: 親子ゾーンが同じ権威サーバーのため、親子 NS 情報を比較しません');
});