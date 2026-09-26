import express from 'express';
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
const app = express();
app.use(express.json());
app.use(express.static('public'));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

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
        ? `ADDITIONAL SECTION の sibling glue [${siblingGlueRecords.map(record => `${normalizeDnsName(record.name)}: ${record.data}`).join(', ')}] は、本ツールの動作モードが strict glue のため採用せず、名前解決を行います。`
        : '';
    const unrelatedNote = unrelatedAddressRecords.length > 0
        ? `RFC 9499 で Unrelated と分類される ADDITIONAL SECTION のアドレス [${unrelatedAddressRecords.map(record => `${normalizeDnsName(record.name)}: ${record.data}`).join(', ')}] は、偽装アドレスを使わせる攻撃への対策として採用しません。`
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

function getKnownAddresses(additionals) {
    const knownAddresses = new Map();
    for (const record of additionals) {
        if (record.type !== 'A' && record.type !== 'AAAA') continue;
        const name = normalizeDnsName(record.name);
        const addresses = knownAddresses.get(name) || [];
        if (!addresses.includes(record.data)) addresses.push(record.data);
        knownAddresses.set(name, addresses);
    }
    return knownAddresses;
}

function getAddressesForName(addressRecords, nsName) {
    const normalized = normalizeDnsName(nsName);
    return addressRecords
        .filter(record => normalizeDnsName(record.name) === normalized)
        .map(record => record.data);
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

function createQueryFunction(dependencies) {
    const query = dependencies.queryDirectlyUDP || queryDirectlyUDP;
    if (!dependencies.signal) return query;
    return (name, serverIp, cache, qType, options = {}) =>
        query(name, serverIp, cache, qType, { ...options, signal: dependencies.signal });
}

async function getZoneApex(domain, dnsResponseCache, dependencies = {}) {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = createQueryFunction(dependencies);
    const resolverDependencies = { ...dependencies, dnsResponseCache };
    let currentNs = 'a.root-servers.net';
    let currentZone = '';
    let currentServerIPs = await resolveIPs(currentNs, resolverDependencies);
    let currentServerNameMap = Object.fromEntries((currentServerIPs || []).map(serverIp => [serverIp, currentNs]));
    let parentNs = '';
    let parentServerIPs = [];
    let parentServerNameMap = {};
    let parentZone = '';
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
                pushExplorationLog('NETWORK_ERROR', `ゾーン頂点探索中のエラー (${serverIp}): ${res.error}${res.detail ? ' - ' + res.detail : ''}`, currentNs, currentParent, { parentLogId: currentParentLogId });
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

            for (const { serverIp } of authoritativeResponses) {
                const dsResponse = await queryUDP(qname, serverIp, dnsResponseCache, 'DS');
                if (dsResponse.error) continue;

                const dsAnswers = dsResponse.answers || [];
                if (dsAnswers.some(record => record.type === 'DS' && normalizeDnsName(record.name) === qname)) {
                    dsConfirmsDelegation = true;
                    break;
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
        const referralAddressRecords = getReferralAddressRecords(delegation.additionals, nextNsNames, delegation.nextZone, currentZone);
        const inBailiwickGlueRecords = referralAddressRecords.filter(record => isInBailiwickGlue(record, nextNsNames, delegation.nextZone));
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
                ips: await resolveIPs(nsName, resolverDependencies)
            })))
            : [];
        resolvedIPsByName.forEach(({ nsName, ips }) => {
            (ips || []).filter(Boolean).forEach(serverIp => {
                if (!nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = nsName;
            });
        });
        const fallbackReferralIPs = resolvedIPsByName
            .filter(({ ips }) => !ips || ips.length === 0)
            .flatMap(({ nsName }) => getAddressesForName(referralAddressRecords, nsName));
        const fallbackAddressNotes = resolvedIPsByName
            .filter(({ ips }) => !ips || ips.length === 0)
            .map(({ nsName }) => ({ nsName, addresses: getAddressesForName(referralAddressRecords, nsName) }))
            .filter(({ addresses }) => addresses.length > 0)
            .map(({ nsName, addresses }) => `${nsName}: [${addresses.join(', ')}]`);
        fallbackReferralIPs.forEach(serverIp => {
            const referralRecord = referralAddressRecords.find(record => record.data === serverIp && nextNsNames.includes(normalizeDnsName(record.name)));
            if (referralRecord && !nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = normalizeDnsName(referralRecord.name);
        });
        const nextServerIPs = [...new Set([...glueIPs, ...resolvedIPsByName.flatMap(({ ips }) => (ips || []).filter(Boolean)), ...fallbackReferralIPs])];
        const unresolvedNsNames = resolvedIPsByName
            .filter(({ nsName, ips }) => (!ips || ips.length === 0) && getAddressesForName(referralAddressRecords, nsName).length === 0)
            .map(({ nsName }) => nsName);

        const delegationLog = pushExplorationLog('FOLLOW_DELEGATION', `${qname} に対して ${nextNsNames.join(', ')} を示しました。 (${delegation.serverIp})`, currentNs, currentParent, {
            parentLogId: currentParentLogId,
            nextServer: nextNsNames,
            glueIPs,
            fallbackAddressNotes,
            rfc9471: summarizeRfc9471Referral(delegation.nsRecords, delegation.additionals, '', currentZone),
            nsResolutionWarning: unresolvedNsNames.length > 0 ? { names: unresolvedNsNames } : null
        });

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

async function traceDomain(domain, servers, dnsResponseCache, parentIP = null, currentDepth = 1, expectedNSList = [], parentGlueMap = {}, dependencies = {}, serverNameMap = {}, currentZone = '') {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = createQueryFunction(dependencies);
    const resolverDependencies = { ...dependencies, dnsResponseCache };
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

        if (res.error === 'SEND_ERROR' || res.error === 'SOCKET_ERROR' || res.error === 'DECODE_ERROR') {
            logEntry.status = 'NETWORK_ERROR';
            logEntry.detail = `エラー: ${res.detail}`;
            results.push(logEntry);
            return results;
        }

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        const answers = res.answers || [];
        const authorities = res.authorities || [];
        const additionals = res.additionals || [];

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

        const nsRecords = authorities.filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
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
            const fallbackAddressNotes = [];

            for (const ns of nsRecords) {
                const nsKey = normalizeDnsName(ns.data);
                nextGlueMap[nsKey] = [];

                const matchedAddressRecords = getReferralAddressRecords(additionals, [nsKey], delegatedZone, currentZone);
                const matchedGlues = matchedAddressRecords.filter(record => isInBailiwickGlue(record, [nsKey], delegatedZone));
                matchedGlues.forEach(g => {
                    nextGlueMap[nsKey].push(g.data);
                    nextServerIPs.push(g.data);
                    if (!nextServerNameMap[g.data]) nextServerNameMap[g.data] = nsKey;
                });

                if (matchedGlues.length === 0) {
                    const resolvedIPs = await resolveIPs(ns.data, resolverDependencies);
                    const nextIPs = resolvedIPs && resolvedIPs.length > 0
                        ? resolvedIPs
                        : matchedAddressRecords.map(record => record.data);
                    if ((!resolvedIPs || resolvedIPs.length === 0) && nextIPs.length > 0) {
                        fallbackAddressNotes.push(`${nsKey}: [${nextIPs.join(', ')}]`);
                    }

                    nextIPs.forEach(ip => {
                        nextServerIPs.push(ip);
                        if (!nextServerNameMap[ip]) nextServerNameMap[ip] = nsKey;
                    });
                }
            }

            logEntry.fallbackAddressNotes = fallbackAddressNotes;
            nextServerIPs = [...new Set(nextServerIPs)];

            if (nextServerIPs.length > 0) {
                const childResults = await traceDomain(domain, nextServerIPs, dnsResponseCache, serverIp, currentDepth + 1, currentNSNames, nextGlueMap, dependencies, nextServerNameMap, delegatedZone);
                results = results.concat(childResults);
            } else {
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

app.post('/api/trace', async (req, res) => {
    const domain = normalizeUserDomain(req.body?.domain);
    if (!domain) {
        return res.status(400).json({ error: 'ドメイン名を入力してください' });
    }

    const dnsResponseCache = new Map();
    const abortController = new AbortController();
    const abortOnResponseClose = () => {
        if (!res.writableEnded) abortController.abort();
    };
    res.once('close', abortOnResponseClose);
    let zoneApexTimer;

    try {
        const zoneApexInfo = await Promise.race([
            getZoneApex(domain, dnsResponseCache, { signal: abortController.signal }),
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
                : await resolveServerIPs('a.root-servers.net', { dnsResponseCache, signal: abortController.signal });
            const serverNameMap = zoneApexInfo.parentServerNameMap || Object.fromEntries(serverList.map(serverIp => [serverIp, zoneApexInfo.parentNs || 'a.root-servers.net']));
            traceLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {}, { signal: abortController.signal }, serverNameMap, zoneApexInfo.parentZone || '');
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

        res.json({
            success: true,
            parentDelegationUnavailable: zoneApexInfo.parentDelegationUnavailable === true,
            zoneApexLog: [...explorationLog],
            traceLog: [...traceLog]
        });
    } catch (error) {
        if (!res.destroyed) res.status(500).json({ success: false, error: error.message });
    } finally {
        clearTimeout(zoneApexTimer);
        res.off('close', abortOnResponseClose);
    }
});

const PORT = 3001;

function startServer() {
    const server = app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
    server.timeout = 120000;
    return server;
}

export {
    app,
    getMinimizedQnames,
    hasParentChildRelationship,
    isInBailiwickGlue,
    isIPv6,
    getZoneApex,
    normalizeDnsName,
    normalizeUserDomain,
    queryDirectlyUDP,
    resolveServerIPs,
    summarizeRfc9471Referral,
    traceDomain,
    startServer
};
