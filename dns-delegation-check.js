import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import net from 'net';
import path from 'path';
import dnsPacket from 'dns-packet';	// https://github.com/mafintosh/dns-packet
import { fileURLToPath } from 'url';
import {
    isIPv6,
    normalizeDnsName,
    isSubdomainOrEqual,
    hasParentChildRelationship,
    isInBailiwickGlue,
    queryDirectlyUDP,
    resolveServerIPs
} from 'dns-self-resolver';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 1 リクエストあたりの DNS 問い合わせ数の上限 (一般的なドメインは 50〜150 件程度)。
const MAX_QUERIES_PER_TRACE = 1000;
// 1 つの referral から追跡する NS アドレス数の上限。
const MAX_NS_ADDRESSES_PER_REFERRAL = 32;
const MAX_CONCURRENT_TRACES = 8;
const MAX_CONCURRENT_TRACES_PER_CLIENT = 2;
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX_REQUESTS_PER_CLIENT = 10;

// IANA IPv4/IPv6 Special-Purpose Address Registry のうち、インターネット上の権威サーバーとして
// 到達すべきでない範囲。内部ネットワークへの問い合わせ (SSRF) を防ぐ。
const NON_PUBLIC_IPV4 = new net.BlockList();
[
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
    ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
    ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
].forEach(([address, prefix]) => NON_PUBLIC_IPV4.addSubnet(address, prefix, 'ipv4'));
const GLOBAL_UNICAST_IPV6 = new net.BlockList();
GLOBAL_UNICAST_IPV6.addSubnet('2000::', 3, 'ipv6');
const NON_PUBLIC_IPV6 = new net.BlockList();
[
    ['2001::', 32], ['2001:2::', 48], ['2001:10::', 28], ['2001:20::', 28],
    ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]
].forEach(([address, prefix]) => NON_PUBLIC_IPV6.addSubnet(address, prefix, 'ipv6'));

function isPublicServerIP(ip) {
    const address = String(ip || '');
    try {
        switch (net.isIP(address)) {
            case 4:
                return !NON_PUBLIC_IPV4.check(address, 'ipv4');
            case 6:
                // IPv4-mapped (::ffff:0:0/96)、NAT64、ULA、リンクローカル等は 2000::/3 外のため拒否される。
                return !address.includes('%') &&
                    GLOBAL_UNICAST_IPV6.check(address, 'ipv6') &&
                    !NON_PUBLIC_IPV6.check(address, 'ipv6');
            default:
                return false;
        }
    } catch {
        return false;
    }
}

const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const inlineScriptHashes = [...indexHtml.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map(([, script]) => `'sha256-${crypto.createHash('sha256').update(script, 'utf8').digest('base64')}'`);
const CONTENT_SECURITY_POLICY = [
    "default-src 'none'",
    `script-src ${inlineScriptHashes.join(' ') || "'none'"}`,
    "style-src 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
].join('; ');

function createApp({ queryDirectlyUDP: queryUDP = queryDirectlyUDP, resolveServerIPs: resolveIPs = resolveServerIPs } = {}) {
    const app = express();
    app.disable('x-powered-by');
    // nginx 等のローカルリバースプロキシ経由の X-Forwarded-For のみ信頼する。
    app.set('trust proxy', 'loopback');
    app.use((req, res, next) => {
        res.set({
            'Content-Security-Policy': CONTENT_SECURITY_POLICY,
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin'
        });
        next();
    });
    app.use(express.json({ limit: '1kb' }));
    app.use(express.static(path.join(__dirname, 'public')));
    app.get(['/','/en','/en/'], (req, res) => {
        const isEnglish = req.path.startsWith('/en');
        const html = isEnglish
            ? indexHtml.replace('<html lang="ja">', '<html lang="en">')
                .replace('<title>DNS委任チェッカー</title>', '<title>DNS Delegation Checker</title>')
            : indexHtml;
        res.type('html').send(html);
    });
    const dnsDependencies = { queryDirectlyUDP: queryUDP, resolveServerIPs: resolveIPs };
    app.post('/api/trace', (req, res) => handleTrace(req, res, dnsDependencies));

    // 不正な JSON 等でスタックトレースを含む既定のエラーページを返さない。
    app.use((error, req, res, next) => {
        if (res.headersSent) return next(error);
        const status = Number.isInteger(error?.status) && error.status >= 400 && error.status < 500 ? error.status : 500;
        if (status === 500) console.error('[http]', error);
        res.status(status).json({ success: false, error: status === 500 ? '内部エラーが発生しました。' : '不正なリクエストです。' });
    });
    return app;
}

const activeTracesByClient = new Map();
const recentRequestsByClient = new Map();
let activeTraceCount = 0;

function pruneRateLimitEntries(now) {
    for (const [client, timestamps] of recentRequestsByClient) {
        const recent = timestamps.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW_MS);
        if (recent.length > 0) recentRequestsByClient.set(client, recent);
        else recentRequestsByClient.delete(client);
    }
}
setInterval(() => pruneRateLimitEntries(Date.now()), RATE_LIMIT_WINDOW_MS).unref();

function acquireTraceSlot(req, res) {
    const client = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const recent = (recentRequestsByClient.get(client) || []).filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW_MS);

    if (recent.length >= RATE_LIMIT_MAX_REQUESTS_PER_CLIENT) {
        res.set('Retry-After', String(Math.ceil((RATE_LIMIT_WINDOW_MS - (now - recent[0])) / 1000)));
        res.status(429).json({ success: false, error: 'リクエストが多すぎます。しばらく待ってから再度お試しください。' });
        return null;
    }
    if (activeTraceCount >= MAX_CONCURRENT_TRACES || (activeTracesByClient.get(client) || 0) >= MAX_CONCURRENT_TRACES_PER_CLIENT) {
        res.set('Retry-After', '10');
        res.status(503).json({ success: false, error: 'サーバーが混み合っています。しばらく待ってから再度お試しください。' });
        return null;
    }

    recent.push(now);
    recentRequestsByClient.set(client, recent);
    activeTraceCount++;
    activeTracesByClient.set(client, (activeTracesByClient.get(client) || 0) + 1);

    let released = false;
    return () => {
        if (released) return;
        released = true;
        activeTraceCount--;
        const remaining = (activeTracesByClient.get(client) || 1) - 1;
        if (remaining > 0) activeTracesByClient.set(client, remaining);
        else activeTracesByClient.delete(client);
    };
}

function normalizeUserDomain(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';

    const candidate = raw.replace(/^https?:\/\//i, '').replace(/\/$/, '');
    const normalized = normalizeDnsName(candidate);

    if (!normalized) return '';
    if (normalized.length > 253) return '';
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(normalized)) {
        return '';
    }

    return normalized;
}

function summarizeRfc9471Referral(nsRecords, additionals, retryFrom = '', parentZone) {
    const delegatedZone = normalizeDnsName(nsRecords[0]?.name);
    const nsNames = nsRecords.map(record => normalizeDnsName(record.data));
    const { inDomainGlueRecords, siblingGlueRecords, unrelatedAddressRecords } = classifyReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone);
    const inDomainNs = nsNames.filter(nsName => isSubdomainOrEqual(nsName, delegatedZone));
    const inDomainGlueNames = [...new Set(inDomainGlueRecords
        .map(record => normalizeDnsName(record.name)))];
    const missingInDomainGlueNames = inDomainNs.filter(nsName => !inDomainGlueNames.includes(nsName));
    const transportNote = retryFrom === 'udp-truncated'
        ? 'UDP 応答は TC=1 のため TCP で再取得しました。'
        : 'UDP 応答は TC=0 でした。';
    const inDomainNote = inDomainNs.length === 0
        ? 'in-domain NS はありません。'
        : missingInDomainGlueNames.length === 0
            ? `in-domain glue: [${inDomainGlueNames.join(', ')}]`
            : `ADDITIONAL SECTION に存在しない in-domain NS [${missingInDomainGlueNames.join(', ')}] は、親ゾーンで利用可能な glue が存在するかは応答だけでは判定できません。`;
    const siblingNote = siblingGlueRecords.length > 0
        ? `ADDITIONAL SECTION の [${siblingGlueRecords.map(record => `${normalizeDnsName(record.name)}: ${record.data}`).join(', ')}] は sibling glue ですが、本ツールの動作モードが strict glue のため採用せず、名前解決を行います。`
        : '';
    const unrelatedNote = unrelatedAddressRecords.length > 0
        ? `ADDITIONAL SECTION の [${unrelatedAddressRecords.map(record => `${normalizeDnsName(record.name)}: ${record.data}`).join(', ')}] は RFC 9499 では unrelated に分類されるため、偽装アドレスを使わせる攻撃への対策として採用せず、名前解決を行います。`
        : '';

    return [transportNote, inDomainNote, siblingNote, unrelatedNote].filter(Boolean).join('\r');
}

function classifyReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone = normalizeDnsName(delegatedZone).split('.').slice(1).join('.')) {
    const addressRecords = additionals.filter(record =>
        (record.type === 'A' || record.type === 'AAAA') &&
        nsNames.includes(normalizeDnsName(record.name))
    );
    const inDomainGlueRecords = addressRecords.filter(record =>
        isInBailiwickGlue(record, nsNames, delegatedZone)
    );
    const siblingGlueRecords = addressRecords.filter(record =>
        !inDomainGlueRecords.includes(record) &&
        (!parentZone || isSubdomainOrEqual(record.name, parentZone))
    );
    const unrelatedAddressRecords = addressRecords.filter(record =>
        !inDomainGlueRecords.includes(record) && !siblingGlueRecords.includes(record)
    );

    return { inDomainGlueRecords, siblingGlueRecords, unrelatedAddressRecords };
}

function getReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone) {
    const { inDomainGlueRecords } = classifyReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone);
    return inDomainGlueRecords;
}

function buildGlueInfo(additionals, nsRecords, parentZone, server, serverName) {
    const delegatedZone = normalizeDnsName(nsRecords[0]?.name);
    const nsNames = nsRecords.map(record => normalizeDnsName(record.data));
    const { inDomainGlueRecords, siblingGlueRecords, unrelatedAddressRecords } =
        classifyReferralAddressRecords(additionals, nsNames, delegatedZone, parentZone);

    return {
        server,
        serverName,
        parentZone: parentZone || '.',
        delegatedZone,
        records: additionals.filter(record => record.type !== 'OPT').map(record => ({
            ...record,
            classification: inDomainGlueRecords.includes(record) ? 'in-domain'
                : siblingGlueRecords.includes(record) ? 'sibling domain'
                : unrelatedAddressRecords.includes(record) ? 'unrelated'
                : null
        }))
    };
}

function buildAddressSelectionNotes(blockedServerIPs, truncatedServerIPs, serverNameMap) {
    const formatIPs = ips => ips.map(ip => serverNameMap[ip] ? `${serverNameMap[ip]}: ${ip}` : ip).join(', ');
    const notes = [];
    if (blockedServerIPs.length > 0) {
        notes.push(`[${formatIPs(blockedServerIPs)}] はグローバルユニキャストアドレスではないため、問い合わせを行いません。`);
    }
    if (truncatedServerIPs.length > 0) {
        notes.push(`NS の IP アドレスが上限 (${MAX_NS_ADDRESSES_PER_REFERRAL}) を超えたため、[${formatIPs(truncatedServerIPs)}] は追跡しません。`);
    }
    return notes.length > 0 ? { addressSelectionNotes: notes } : {};
}

async function resolveAuthoritativeServerIPs(name, serverIp, dnsResponseCache, queryUDP) {
    const responses = await Promise.all(['A', 'AAAA'].map(async type =>
        queryUDP(name, serverIp, dnsResponseCache, type)
    ));
    return [...new Set(responses.flatMap(response =>
        (response.error ? [] : (response.answers || []))
            .filter(record =>
                (record.type === 'A' || record.type === 'AAAA') &&
                normalizeDnsName(record.name) === normalizeDnsName(name)
            )
            .map(record => record.data)
    ))];
}

function getMinimizedQnames(domain) {
    const labels = normalizeDnsName(domain).split('.');
    return labels.map((_, index) => labels.slice(index).join('.')).reverse();
}

function getServerAddressPolicy(dependencies) {
    if (typeof dependencies.isAllowedServerIP === 'function') return dependencies.isAllowedServerIP;
    // 宛先制限は実ネットワークへ送信する既定トランスポートに適用する (テスト用モック等は対象外)。
    return dependencies.queryDirectlyUDP ? () => true : isPublicServerIP;
}

function createQueryFunction(dependencies) {
    const query = dependencies.queryDirectlyUDP || queryDirectlyUDP;
    const isAllowedServerIP = getServerAddressPolicy(dependencies);
    const budget = dependencies.queryBudget;
    return (name, serverIp, cache, qType, options) => {
        if (!isAllowedServerIP(serverIp)) {
            return Promise.resolve({
                error: 'BLOCKED_ADDRESS', domain: name, serverIp, qType, retryable: false,
                detail: `${serverIp} はグローバルユニキャストアドレスではないため、問い合わせを行いません。`
            });
        }
        if (budget) {
            if (budget.remaining <= 0) {
                budget.exhausted = true;
                return Promise.resolve({
                    error: 'QUERY_LIMIT_EXCEEDED', domain: name, serverIp, qType, retryable: false,
                    detail: `1 回の検査で実行できる DNS 問い合わせ数の上限 (${MAX_QUERIES_PER_TRACE}) に達しました。`
                });
            }
            budget.remaining--;
        }
        return dependencies.signal
            ? query(name, serverIp, cache, qType, { ...(options || {}), signal: dependencies.signal })
            : query(name, serverIp, cache, qType, options);
    };
}

function isQueryBudgetExhausted(dependencies) {
    return !!dependencies.queryBudget && dependencies.queryBudget.remaining <= 0;
}

function createResolverDependencies(dependencies, dnsResponseCache, queryUDP) {
    return { ...dependencies, dnsResponseCache, queryDirectlyUDP: queryUDP };
}

// 宛先として許可されない NS アドレスを除外し、1 referral あたりの追跡数を制限する。
function selectServerIPs(ips, dependencies) {
    const isAllowedServerIP = getServerAddressPolicy(dependencies);
    const uniqueIPs = [...new Set(ips)];
    const blocked = uniqueIPs.filter(ip => !isAllowedServerIP(ip));
    const allowed = uniqueIPs.filter(ip => isAllowedServerIP(ip));
    return {
        allowed: allowed.slice(0, MAX_NS_ADDRESSES_PER_REFERRAL),
        blocked,
        truncated: allowed.slice(MAX_NS_ADDRESSES_PER_REFERRAL)
    };
}

async function getZoneApex(domain, dnsResponseCache, dependencies = {}) {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = createQueryFunction(dependencies);
    const resolverDependencies = createResolverDependencies(dependencies, dnsResponseCache, queryUDP);
    let currentNs = 'a.root-servers.net';
    let currentZone = '';
    let currentServerIPs = await resolveIPs(currentNs, resolverDependencies);
    let currentServerNameMap = Object.fromEntries((currentServerIPs || []).map(serverIp => [serverIp, currentNs]));
    let parentNs = '';
    let parentServerIPs = [];
    let parentServerNameMap = {};
    let parentZone = '';
    let parentGlueInfos = [];
    let zoneApex = '';
    let hasCnameOrDname = false;
    let hasAddressRecordWithoutDelegation = false;
    let hasNoDelegationForQname = false;
    let hasZoneApexLookupFailure = false;
    let explorationLogs = [];
    let lastDelegatedZone = '';
    let lastDelegatedOrder = -1;
    let lastColocatedDelegation = null;
    let colocatedParentLogId = null;

    const pushExplorationLog = (status, detail, server = currentNs, parent = parentNs || null, extra = {}) => {
        const logEntry = {
            id: `zone-apex-${explorationLogs.length}`,
            server,
            parent,
            status,
            detail,
            nsMatch: null,
            glueMatch: null,
            ...extra
        };
        explorationLogs.push(logEntry);
        return logEntry;
    };

    const minimizedQnames = getMinimizedQnames(domain);
    let qnameIndex = 0;
    let parentDelegationUnavailable = false;

    // ラベルを右から一つずつ増やし、親ゾーンから各ゾーンカットを取得する。
    while (qnameIndex < minimizedQnames.length && currentServerIPs?.length) {
        const qname = minimizedQnames[qnameIndex];
        // 親子同居では currentNs と parentNs が同じになるため、自己参照のツリーを作らない。
        const currentParent = parentNs && parentNs !== currentNs ? parentNs : null;
        const currentParentLogId = parentNs === currentNs ? colocatedParentLogId : null;
        let delegation = null;
        const authoritativeResponses = [];
        const serverResponses = await Promise.all(currentServerIPs.map(async (serverIp) => ({
            serverIp,
            res: await queryUDP(qname, serverIp, dnsResponseCache, 'NS')
        })));

        for (const { serverIp, res } of serverResponses) {
            if (res.error) {
                const status = res.error === 'QUERY_LIMIT_EXCEEDED' ? 'QUERY_LIMIT_EXCEEDED' : 'NETWORK_ERROR';
                pushExplorationLog(status, `ゾーン頂点探索中のエラー (${serverIp}): ${res.error}${res.detail ? ' - ' + res.detail : ''}`, currentNs, currentParent, { parentLogId: currentParentLogId });
                continue;
            }

            const isAuthoritative = (res.flags & (dnsPacket.AUTHORITATIVE_ANSWER || 1024)) !== 0;
            const answers = res.answers || [];
            const authorities = res.authorities || [];

            const cnameRecord = answers.find(r => r.type === 'CNAME');
            const dnameRecord = answers.find(r => r.type === 'DNAME');
            if (cnameRecord || dnameRecord) {
                const detail = cnameRecord
                    ? `入力名は CNAME (${normalizeDnsName(cnameRecord.name)} -> ${normalizeDnsName(cnameRecord.data)}) です。CNAME の委任先は追跡せず、ゾーン頂点としての委任検査を終了します。 (${serverIp})`
                    : `回答に DNAME が含まれており、ゾーン頂点を確定できませんでした。 (${serverIp})`;
                pushExplorationLog(cnameRecord ? 'CNAME_FOUND' : 'DNAME_FOUND', detail, currentNs, currentParent, { parentLogId: currentParentLogId });
                hasCnameOrDname = true;
                break;
            }

            const validNsRecords = authorities.filter(r => r.type === 'NS' && normalizeDnsName(r.name) === qname);
            if (validNsRecords.length > 0) {
                delegation = { nsRecords: validNsRecords, additionals: res.additionals || [], serverIp, nextZone: qname };
                break;
            }

            const addressRecord = answers.find(record =>
                (record.type === 'A' || record.type === 'AAAA') && normalizeDnsName(record.name) === qname
            );
            if (addressRecord) {
                pushExplorationLog(
                    'ADDRESS_RECORD_FOUND',
                    `${qname} は ${addressRecord.type} レコードを持つホスト名であり、AUTHORITY SECTION に下位ゾーンへの委任 NS レコードがありません。ゾーン名を指定して委任状態を確認してください。 (${serverIp})`,
                    currentNs,
                    currentParent,
                    { parentLogId: currentParentLogId }
                );
                hasAddressRecordWithoutDelegation = true;
                break;
            }

            if (isAuthoritative) {
                authoritativeResponses.push({ serverIp, answers, authorities });
                pushExplorationLog('AUTHORITATIVE_NO_DELEGATION', `${qname} に対して ${currentNs} は権威応答を返し、下位ゾーンへの委任はありません。 (${serverIp})`, currentNs, currentParent, { parentLogId: currentParentLogId });
                continue;
            }

            pushExplorationLog('UNEXPECTED_RESPONSE', `委任情報を特定できない応答です (${serverIp}, qname: ${qname}, rcode: ${res.rcode}, AA: ${isAuthoritative})。`, currentNs, currentParent, { parentLogId: currentParentLogId });
        }

        if (zoneApex || hasCnameOrDname || hasNoDelegationForQname) break;
        if (!delegation) {
            const childNsResponse = authoritativeResponses.find(({ answers }) =>
                answers.some(record => record.type === 'NS' && normalizeDnsName(record.name) === qname)
            );
            let dsConfirmsDelegation = false;

            if (!childNsResponse) {
                for (const { serverIp } of authoritativeResponses) {
                    const dsResponse = await queryUDP(qname, serverIp, dnsResponseCache, 'DS');
                    if (dsResponse.error) continue;

                    const dsAnswers = dsResponse.answers || [];
                    if (dsAnswers.some(record => record.type === 'DS' && normalizeDnsName(record.name) === qname)) {
                        dsConfirmsDelegation = true;
                        break;
                    }
                }
            }

            if (childNsResponse || dsConfirmsDelegation) {
                parentNs = currentNs;
                parentServerIPs = currentServerIPs;
                lastColocatedDelegation = { zoneApex: qname, dsConfirmsDelegation, order: qnameIndex };
                const colocatedLog = pushExplorationLog(
                    'COLOCATED_DELEGATION',
                    `${qname} は親ゾーンと同じ権威サーバーに存在する子ゾーンです。親側の referral は取得できず、親が保持する委任 NS との比較は DNS 問い合わせだけでは実施できません。${dsConfirmsDelegation ? ' DS レコードでゾーンカットを確認しました。' : ' 子ゾーンの apex NS 応答を確認しました。'}`,
                    currentNs,
                    currentParent
                );
                colocatedParentLogId = colocatedLog.id;
                qnameIndex++;
                continue;
            }

            if (authoritativeResponses.length > 0 && !lastColocatedDelegation) {
                const isLastQname = qnameIndex === minimizedQnames.length - 1;
                if (isLastQname) {
                    pushExplorationLog(
                        'NO_DELEGATION_FOR_QNAME',
                        `${qname} は権威サーバーから下位ゾーンへの委任 NS レコードを取得できませんでした。入力名はゾーン頂点ではないため、委任状態を確認できません。`,
                        currentNs,
                        currentParent,
                        { parentLogId: currentParentLogId }
                    );
                    hasNoDelegationForQname = true;
                    break;
                }
            }

            qnameIndex++;
            continue;
        }

        const nextNsNames = delegation.nsRecords.map(record => normalizeDnsName(record.data));
        const inBailiwickGlueRecords = getReferralAddressRecords(delegation.additionals, nextNsNames, delegation.nextZone, currentZone);
        const inBailiwickGlueNames = new Set(inBailiwickGlueRecords.map(record => normalizeDnsName(record.name)));
        const glueIPs = inBailiwickGlueRecords.map(record => record.data);
        const nextServerNameMap = {};
        glueIPs.forEach(serverIp => {
            const glueRecord = inBailiwickGlueRecords.find(record => record.data === serverIp);
            if (glueRecord && !nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = normalizeDnsName(glueRecord.name);
        });
        // in-bailiwick glue が無い NS 名は、他の NS 名が glue を持っていても個別に名前解決を試みる。
        const nsNamesNeedingResolution = nextNsNames.filter(nsName => !inBailiwickGlueNames.has(nsName));
        const resolvedIPsByName = nsNamesNeedingResolution.length > 0
            ? await Promise.all(nsNamesNeedingResolution.map(async nsName => ({
                nsName,
                ips: isQueryBudgetExhausted(dependencies) ? null : await resolveIPs(nsName, resolverDependencies)
            })))
            : [];
        resolvedIPsByName.forEach(({ nsName, ips }) => {
            (ips || []).filter(Boolean).forEach(serverIp => {
                if (!nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = nsName;
            });
        });
        const candidateServerIPs = [...new Set([...glueIPs, ...resolvedIPsByName.flatMap(({ ips }) => (ips || []).filter(Boolean))])];
        const { allowed: nextServerIPs, blocked: blockedServerIPs, truncated: truncatedServerIPs } = selectServerIPs(candidateServerIPs, dependencies);
        const unresolvedNsNames = resolvedIPsByName
            .filter(({ ips }) => !ips || ips.length === 0)
            .map(({ nsName }) => nsName);

        parentGlueInfos = serverResponses.map(({ serverIp, res }) => {
            const serverName = currentServerNameMap[serverIp] || currentNs;
            if (res.error) {
                return {
                    server: serverIp, serverName, parentZone: currentZone || '.',
                    delegatedZone: qname, records: null,
                    error: res.error, detail: res.detail || ''
                };
            }
            const nsRecords = (res.authorities || []).filter(record =>
                record.type === 'NS' && normalizeDnsName(record.name) === qname
            );
            return {
                ...buildGlueInfo(res.additionals || [], nsRecords, currentZone, serverIp, serverName),
                delegatedZone: qname
            };
        });

        const delegationLog = pushExplorationLog('FOLLOW_DELEGATION', `${qname} に対して ${nextNsNames.join(', ')} を示しました。 (${delegation.serverIp})`, currentNs, currentParent, {
            parentLogId: currentParentLogId,
            nextServer: nextNsNames,
            glueIPs,
            glueInfo: buildGlueInfo(delegation.additionals, delegation.nsRecords, currentZone, delegation.serverIp, currentServerNameMap[delegation.serverIp] || currentNs),
            fallbackAddressNotes: [],
            ...buildAddressSelectionNotes(blockedServerIPs, truncatedServerIPs, nextServerNameMap),
            rfc9471: summarizeRfc9471Referral(delegation.nsRecords, delegation.additionals, '', currentZone),
            nsResolutionWarning: unresolvedNsNames.length > 0 ? { names: unresolvedNsNames } : null
        });

        if (nextServerIPs.length === 0 && blockedServerIPs.length > 0) {
            pushExplorationLog(
                'LAME_DELEGATION_NON_PUBLIC_ADDRESS',
                `委任先 NS レコード (${nextNsNames.join(', ')}) の IP アドレス [${blockedServerIPs.join(', ')}] はグローバルユニキャストアドレスではないため、ゾーン頂点を確認できません。`,
                currentNs,
                currentParent
            );
            hasZoneApexLookupFailure = true;
            break;
        }

        if (nextServerIPs.length === 0) {
            pushExplorationLog(
                'LAME_DELEGATION_NO_NS_IP_ADDRESS',
                `委任先 NS レコード (${nextNsNames.join(', ')}) の IP アドレスを取得できないため、ゾーン頂点を確認できません。`,
                currentNs,
                currentParent
            );
            hasZoneApexLookupFailure = true;
            break;
        }

        parentNs = currentNs;
        parentServerIPs = [delegation.serverIp];
        parentServerNameMap = {
            [delegation.serverIp]: currentServerNameMap[delegation.serverIp] || currentNs
        };
        currentNs = nextNsNames.join(', ');
        currentServerIPs = nextServerIPs;
        currentServerNameMap = nextServerNameMap;
        parentZone = currentZone;
        currentZone = delegation.nextZone;
        lastDelegatedZone = delegation.nextZone;
        lastDelegatedOrder = qnameIndex;
        qnameIndex++;

        // 最終入力名への委任がある場合は、委任先で CNAME/DNAME か確認する。
        if (qnameIndex >= minimizedQnames.length) {
            const childResponses = await Promise.all(currentServerIPs.map(async nextServerIp => ({
                serverIp: nextServerIp,
                response: await queryUDP(qname, nextServerIp, dnsResponseCache, 'NS')
            })));
            for (const { serverIp, response: childResponse } of childResponses) {
                if (childResponse.error) continue;

                const childCnameRecord = (childResponse.answers || []).find(record => record.type === 'CNAME');
                const childDnameRecord = (childResponse.answers || []).find(record => record.type === 'DNAME');
                if (childCnameRecord || childDnameRecord) {
                    const detail = childCnameRecord
                        ? `入力名は CNAME (${normalizeDnsName(childCnameRecord.name)} -> ${normalizeDnsName(childCnameRecord.data)}) です。CNAME の委任先は追跡せず、ゾーン頂点としての委任検査を終了します。 (${serverIp})`
                        : `回答に DNAME が含まれており、ゾーン頂点を確定できませんでした。 (${serverIp})`;
                    pushExplorationLog(childCnameRecord ? 'CNAME_FOUND' : 'DNAME_FOUND', detail, currentNs, currentNs, { parentLogId: delegationLog.id });
                    hasCnameOrDname = true;
                    break;
                }
            }
        }
    }

    if (!hasCnameOrDname && !hasZoneApexLookupFailure && lastColocatedDelegation && lastColocatedDelegation.order > lastDelegatedOrder) {
        zoneApex = lastColocatedDelegation.zoneApex;
        parentDelegationUnavailable = true;
        pushExplorationLog('ZONE_APEX_FOUND', `ゾーン頂点を確定: ${zoneApex}。親ゾーンと同じ権威サーバーで提供されているため、親側の委任情報は使用できません。`, currentNs, parentNs || null, { parentLogId: colocatedParentLogId });
    } else if (!hasCnameOrDname && !hasZoneApexLookupFailure && lastDelegatedZone) {
        zoneApex = lastDelegatedZone;
        pushExplorationLog('ZONE_APEX_FOUND', `ゾーン頂点を確定: ${zoneApex}。親ゾーンの委任情報を使用して検査します。`, currentNs, parentNs || null);
    }

    return {
        currentNs: currentNs,
        parentNs: parentNs,
        parentServerIPs: parentServerIPs,
        parentServerNameMap: parentServerNameMap,
        parentZone: parentZone,
        parentGlueInfos: parentDelegationUnavailable || (!zoneApex && !hasZoneApexLookupFailure)
            ? [] : parentGlueInfos,
        zoneApex: zoneApex,
        hasCnameOrDname,
        hasAddressRecordWithoutDelegation,
        hasNoDelegationForQname,
        hasZoneApexLookupFailure,
        parentDelegationUnavailable: parentDelegationUnavailable,
        colocatedDelegation: lastColocatedDelegation,
        explorationLogs: explorationLogs,
        errorLogs: explorationLogs
    };
}

async function traceDomain(domain, servers, dnsResponseCache, parentIP = null, currentDepth = 1, expectedNSList = [], parentGlueMap = {}, dependencies = {}, serverNameMap = {}, currentZone = '', visitedServerIPs = []) {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = createQueryFunction(dependencies);
    const resolverDependencies = createResolverDependencies(dependencies, dnsResponseCache, queryUDP);
    let results = [];
    if (currentDepth > 10) {
        results.push({
            server: servers[0] || '',
            serverName: serverNameMap[servers[0]] || '',
            parent: parentIP,
            status: 'LAME_DELEGATION_MAX_DEPTH',
            detail: `委任チェーンが上限 (${10}) に達したため、以降の追跡を打ち切りました。`,
            nsMatch: null,
            glueMatch: null
        });
        return results;
    }

    const serverResults = await Promise.all(servers.map(async (serverIp) => {
        let results = [];
        let logEntry = {
            server: serverIp,
            serverName: serverNameMap[serverIp] || '',
            parent: parentIP,
            status: 'Querying',
            detail: '',
            nsMatch: null,
            glueMatch: null
        };
        const visitedOnPath = new Set([...visitedServerIPs, serverIp]);

        const res = await queryUDP(domain, serverIp, dnsResponseCache, 'NS');

        if (res.error === 'TIMEOUT') {
            logEntry.status = 'LAME_DELEGATION_TIMEOUT';
            if (res.isCached) {
                logEntry.detail = `サーバーから応答がありません。(キャッシュ再利用)`;
            } else {
                logEntry.detail = `サーバーから応答がありません。`;
            }
            results.push(logEntry);
            return results;
        }

        if (res.error === 'BLOCKED_ADDRESS') {
            logEntry.status = 'LAME_DELEGATION_NON_PUBLIC_ADDRESS';
            logEntry.detail = res.detail;
            results.push(logEntry);
            return results;
        }

        if (res.error === 'QUERY_LIMIT_EXCEEDED') {
            logEntry.status = 'QUERY_LIMIT_EXCEEDED';
            logEntry.detail = res.detail;
            results.push(logEntry);
            return results;
        }

        if (res.error) {
            logEntry.status = 'NETWORK_ERROR';
            logEntry.detail = `エラー: ${res.detail || res.error}`;
            results.push(logEntry);
            return results;
        }

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        const answers = res.answers || [];
        const authorities = res.authorities || [];
        const additionals = res.additionals || [];
        const nsRecords = authorities.filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
        if (currentDepth === 1) {
            logEntry.glueInfo = buildGlueInfo(additionals, nsRecords, currentZone, serverIp, logEntry.serverName);
        }

        const cacheNote = res.isCached ? ' (キャッシュ再利用)' : '';

        if (isAuthoritative && answers.length === 0) {
            logEntry.status = 'LAME_DELEGATION_NO_ZONE';
            logEntry.detail = `AUTHORITYとして指定されていますが、ゾーンを保持していません (NS レコードが存在しません)。${cacheNote}`;
            results.push(logEntry);
            return results;
        }

        if (isAuthoritative && answers.length > 0) {
            logEntry.status = 'SUCCESS';

            const childNSList = answers
                .filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name))
                .map(r => normalizeDnsName(r.data));
            const parentNSListNormalized = expectedNSList.map(ns => normalizeDnsName(ns));

            if (childNSList.length > 0 && parentNSListNormalized.length > 0) {
                const isMatch = childNSList.length === parentNSListNormalized.length &&
                                childNSList.every(ns => parentNSListNormalized.includes(ns));

                if (isMatch) {
                    logEntry.nsMatch = {
                        success: true,
                        msg: `✅ NS 情報一致！${cacheNote}\r委任情報: [${parentNSListNormalized.sort().join(', ')}]`
                    };
                } else {
                    logEntry.nsMatch = {
                        success: false, 
                        msg: `⚠️ NS 情報不一致！\r親が保持する委任情報: [${parentNSListNormalized.sort().join(', ')}]\r子が保持する NS 情報: [${childNSList.sort().join(', ')}]${cacheNote}`
                    };
                    logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
                }
            } else if (childNSList.length === 0 && parentNSListNormalized.length > 0) {
                logEntry.nsMatch = {
                    success: false,
                        msg: `⚠️ NS 情報不一致！\r親が保持する委任情報: [${parentNSListNormalized.sort().join(', ')}]\r子が保持する NS 情報: (NS レコードが存在しません)${cacheNote}`
                };
                logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
            }

            const currentNSName = Object.keys(parentGlueMap).find(name => parentGlueMap[name].includes(serverIp));

            if (currentNSName) {
                const authoritativeIPs = await resolveAuthoritativeServerIPs(currentNSName, serverIp, dnsResponseCache, queryUDP);
                const childIPs = authoritativeIPs.length > 0
                    ? authoritativeIPs
                    : await resolveIPs(currentNSName, { ...resolverDependencies, knownAddresses: parentGlueMap });
                const parentGlueIPs = parentGlueMap[currentNSName] || [];

                if (childIPs) {
                    if (parentGlueIPs.length > 0) {
                        const sortedChild = [...childIPs].sort();
                        const sortedParent = [...parentGlueIPs].sort();
                        const isGlueMatch = sortedChild.length === sortedParent.length &&
                                            sortedChild.every((ip, i) => ip === sortedParent[i]);

                        if (isGlueMatch) {
                            logEntry.glueMatch = {
                                success: true,
                                msg: `✅ IP アドレス一致！【${currentNSName}】\r子の IP アドレス: [${sortedChild.sort().join(', ')}]`
                            };
                        } else {
                            logEntry.glueMatch = {
                                success: false,
                                msg: `⚠️ IP アドレス不一致！【${currentNSName}】\r親が保持する子情報: [${sortedParent.sort().join(', ')}]\r子の IP アドレス: [${sortedChild.sort().join(', ')}]`
                            };
                            logEntry.status = 'LAME_DELEGATION_NOT_MATCH';
                        }
                    }
                } else {
                    logEntry.glueMatch = { 
                        success: false, 
                        msg: `⚠️ IP アドレス不一致！【${currentNSName}】IP アドレスを得られませんでした。`
                    };
                    logEntry.status = 'LAME_DELEGATION_NO_IP_ADDRESS';
                }
            }

            if (logEntry.status !== 'SUCCESS') {
                logEntry.detail = `委任元 (親) と委任先 (子) とで情報が一致していません。${cacheNote}`;
            } else {
                logEntry.detail = `正しく委任できています。${cacheNote}`;
            }
            results.push(logEntry);
            return results;
        }

        if (nsRecords.length > 0) {
            logEntry.status = 'DELEGATED';
            logEntry.detail = `AUTHORITY SECTION に ${nsRecords.length} 個の NS レコード。IP アドレスを以下に列挙。${cacheNote}`;
            results.push(logEntry);

            const currentNSNames = nsRecords.map(r => normalizeDnsName(r.data));
            const delegatedZone = normalizeDnsName(nsRecords[0].name);
            logEntry.rfc9471 = summarizeRfc9471Referral(nsRecords, additionals, res.retryFrom, currentZone);

            let nextGlueMap = {};
            let nextServerIPs = [];
            let nextServerNameMap = {};

            for (const ns of nsRecords) {
                const nsKey = normalizeDnsName(ns.data);
                nextGlueMap[nsKey] = [];

                const matchedGlues = getReferralAddressRecords(additionals, [nsKey], delegatedZone, currentZone);
                matchedGlues.forEach(g => {
                    nextGlueMap[nsKey].push(g.data);
                    nextServerIPs.push(g.data);
                    if (!nextServerNameMap[g.data]) nextServerNameMap[g.data] = nsKey;
                });

                if (matchedGlues.length === 0 && !isQueryBudgetExhausted(dependencies)) {
                    const resolvedIPs = await resolveIPs(ns.data, resolverDependencies);
                    (resolvedIPs || []).filter(Boolean).forEach(ip => {
                        nextServerIPs.push(ip);
                        if (!nextServerNameMap[ip]) nextServerNameMap[ip] = nsKey;
                    });
                }
            }

            logEntry.fallbackAddressNotes = [];
            const { allowed: allowedServerIPs, blocked: blockedServerIPs, truncated: truncatedServerIPs } = selectServerIPs(nextServerIPs, dependencies);
            Object.assign(logEntry, buildAddressSelectionNotes([], truncatedServerIPs, nextServerNameMap));
            for (const blockedServerIp of blockedServerIPs) {
                results.push({
                    server: blockedServerIp,
                    serverName: nextServerNameMap[blockedServerIp] || '',
                    parent: serverIp,
                    status: 'LAME_DELEGATION_NON_PUBLIC_ADDRESS',
                    detail: `委任先 NS の IP アドレス (${blockedServerIp}) はグローバルユニキャストアドレスではないため、問い合わせを行いません。`,
                    nsMatch: null,
                    glueMatch: null
                });
            }
            nextServerIPs = allowedServerIPs;

            if (nextServerIPs.length > 0) {
                const visitedDestinations = nextServerIPs.filter(nextServerIp => visitedOnPath.has(nextServerIp));
                for (const visitedDestination of visitedDestinations) {
                    if (visitedDestination === serverIp) {
                        results.push({
                            server: serverIp,
                            serverName: serverNameMap[serverIp] || '',
                            parent: parentIP,
                            status: 'LAME_DELEGATION_NO_ZONE',
                            detail: `委任先 NS の一部 (${currentNSNames.join(', ')}) が、応答したサーバー自身 (${serverIp}) を指しています。このサーバーは対象ゾーンへの委任応答を返していますが、対象ゾーンについて権威応答していません。`
                        });
                    } else {
                        results.push({
                            server: visitedDestination,
                            serverName: nextServerNameMap[visitedDestination] || '',
                            parent: serverIp,
                            status: 'LAME_DELEGATION_NO_ZONE',
                            detail: `委任先 NS (${currentNSNames.join(', ')}) が、追跡済みのサーバー (${visitedDestination}) を指しています。このサーバーは対象ゾーンへの委任応答を返していますが、対象ゾーンについて権威応答していません。`
                        });
                    }
                }

                const childServerIPs = nextServerIPs.filter(nextServerIp => !visitedOnPath.has(nextServerIp));
                if (visitedDestinations.length === 0 && childServerIPs.length > 0) {
                    const childResults = await traceDomain(domain, childServerIPs, dnsResponseCache, serverIp, currentDepth + 1, currentNSNames, nextGlueMap, dependencies, nextServerNameMap, delegatedZone, [...visitedServerIPs, serverIp]);
                    results = results.concat(childResults);
                }
            } else if (blockedServerIPs.length === 0) {
                results.push({
                    server: currentNSNames.join(', '), parent: serverIp, status: 'LAME_DELEGATION_NO_NS_IP_ADDRESS',
                    detail: `委任先 NS レコード (${currentNSNames.join(', ')}) の IP アドレスを取得できないため、追跡を継続できません。`
                });
            }
        } else {
            logEntry.status = 'LAME_DELEGATION_NO_AUTHORITY_NS';
            logEntry.detail = `権威サーバーが AUTHORITY セクションに NS レコードを持っていません。委任情報が欠落している可能性があります。${cacheNote}`;
            results.push(logEntry);
        }
        return results;
    }));
    return serverResults.flat();
}

async function handleTrace(req, res, dnsDependencies) {
    const domain = typeof req.body?.domain === 'string' ? normalizeUserDomain(req.body.domain) : '';
    if (!domain) {
        return res.status(400).json({ error: 'ドメイン名を入力してください' });
    }

    const releaseTraceSlot = acquireTraceSlot(req, res);
    if (!releaseTraceSlot) return;

    const dnsResponseCache = new Map();
    const abortController = new AbortController();
    const abortOnResponseClose = () => {
        if (!res.writableEnded) abortController.abort();
    };
    res.once('close', abortOnResponseClose);
    let zoneApexTimer;
    const traceDependencies = {
        ...dnsDependencies,
        signal: abortController.signal,
        isAllowedServerIP: isPublicServerIP,
        queryBudget: { remaining: MAX_QUERIES_PER_TRACE, exhausted: false }
    };

    try {
        const zoneApexInfo = await Promise.race([
            getZoneApex(domain, dnsResponseCache, traceDependencies),
            new Promise(resolve => {
                zoneApexTimer = setTimeout(() => {
                    abortController.abort();
                    resolve({
                        timedOut: true,
                        explorationLogs: [{
                            id: 'zone-apex-timeout',
                            server: '',
                            parent: null,
                            status: 'ZONE_APEX_LOOKUP_TIMEOUT',
                            detail: 'ゾーン頂点の探索が 30 秒以内に完了しませんでした。DNS サーバーの応答状況を確認してください。',
                            nsMatch: null,
                            glueMatch: null
                        }]
                    });
                }, 30000);
            })
        ]);
        clearTimeout(zoneApexTimer);
        if (res.destroyed) return;
        const explorationLog = zoneApexInfo.explorationLogs || zoneApexInfo.errorLogs || [];

        let traceLog = [];
        if (!zoneApexInfo.timedOut && zoneApexInfo.zoneApex !== '' && !zoneApexInfo.parentDelegationUnavailable) {
            const serverList = zoneApexInfo.parentServerIPs.length > 0
                ? zoneApexInfo.parentServerIPs
                : await dnsDependencies.resolveServerIPs('a.root-servers.net', createResolverDependencies(traceDependencies, dnsResponseCache, createQueryFunction(traceDependencies))) || [];
            const serverNameMap = zoneApexInfo.parentServerNameMap || Object.fromEntries(serverList.map(serverIp => [serverIp, zoneApexInfo.parentNs || 'a.root-servers.net']));
            traceLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {}, traceDependencies, serverNameMap, zoneApexInfo.parentZone || '');
        } else if (!zoneApexInfo.timedOut && zoneApexInfo.zoneApex !== '' && zoneApexInfo.parentDelegationUnavailable) {
            const dsConfirmation = zoneApexInfo.colocatedDelegation?.dsConfirmsDelegation
                ? ' DS レコードによりゾーンカットの存在は確認しました。'
                : '';
            traceLog = [{
                server: zoneApexInfo.currentNs,
                parent: null,
                status: 'COLOCATED_DELEGATION',
                detail: `${zoneApexInfo.zoneApex} は親ゾーンと同じ権威サーバーで提供されています。親側 referral を取得できないため、親子の NS 情報は比較できません。${dsConfirmation}`,
                nsMatch: null,
                glueMatch: null
            }];
        }

        if (traceDependencies.queryBudget.exhausted) {
            traceLog.push({
                server: '',
                parent: null,
                status: 'QUERY_LIMIT_EXCEEDED',
                detail: `DNS 問い合わせ数が上限 (${MAX_QUERIES_PER_TRACE}) に達したため、検査を途中で打ち切りました。結果は不完全です。`,
                nsMatch: null,
                glueMatch: null
            });
        }

        res.json({
            success: true,
            parentDelegationUnavailable: zoneApexInfo.parentDelegationUnavailable === true,
            parentGlueInfos: zoneApexInfo.parentGlueInfos || [],
            zoneApexLog: [...explorationLog],
            traceLog: [...traceLog]
        });
    } catch (error) {
        console.error(`[trace] ${domain}:`, error);
        if (!res.destroyed && !res.headersSent) res.status(500).json({ success: false, error: '内部エラーが発生しました。' });
    } finally {
        clearTimeout(zoneApexTimer);
        res.off('close', abortOnResponseClose);
        releaseTraceSlot();
    }
}

const app = createApp();

const HOST = '127.0.0.1';
const PORT = 3001;

function startServer() {
    const server = app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
    server.timeout = 120000;
    return server;
}

export {
    app,
    createApp,
    getMinimizedQnames,
    hasParentChildRelationship,
    isInBailiwickGlue,
    isIPv6,
    isPublicServerIP,
    getZoneApex,
    normalizeDnsName,
    normalizeUserDomain,
    queryDirectlyUDP,
    resolveServerIPs,
    summarizeRfc9471Referral,
    traceDomain,
    startServer
};
