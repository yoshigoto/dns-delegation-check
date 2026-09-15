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

function summarizeRfc9471Referral(nsRecords, additionals, retryFrom = '') {
    const delegatedZone = normalizeDnsName(nsRecords[0]?.name);
    const nsNames = nsRecords.map(record => normalizeDnsName(record.data));
    const inDomainNs = nsNames.filter(nsName => isSubdomainOrEqual(nsName, delegatedZone));
    const inDomainGlueNames = [...new Set(additionals
        .filter(record => isInBailiwickGlue(record, nsNames, delegatedZone))
        .map(record => normalizeDnsName(record.name)))];
    const missingInDomainGlueNames = inDomainNs.filter(nsName => !inDomainGlueNames.includes(nsName));
    const nonInDomainAddressNames = [...new Set(additionals
        .filter(record => (record.type === 'A' || record.type === 'AAAA') && nsNames.includes(normalizeDnsName(record.name)) && !isSubdomainOrEqual(record.name, delegatedZone))
        .map(record => normalizeDnsName(record.name)))];
    const transportNote = retryFrom === 'udp-truncated'
        ? 'UDP 応答は TC=1 のため TCP で再取得しました。'
        : 'UDP 応答は TC=0 でした。';
    const inDomainNote = inDomainNs.length === 0
        ? 'in-domain NS はありません。'
        : missingInDomainGlueNames.length === 0
            ? `in-domain glue: [${inDomainGlueNames.join(', ')}]`
            : `ADDITIONAL SECTION に存在しない in-domain NS [${missingInDomainGlueNames.join(', ')}] は、親ゾーンで利用可能な glue が存在するかは応答だけでは判定できません。`;
    const nonInDomainNote = nonInDomainAddressNames.length > 0
        ? `ADDITIONAL SECTION に存在するゾーン外 NS の IP アドレス [${nonInDomainAddressNames.join(', ')}] は sibling glue である可能性がありますが、このツールでは glue として採用しません。`
        : '';

    return [transportNote, inDomainNote, nonInDomainNote].filter(Boolean).join('\r');
}

function getReferralAddressRecords(additionals, nsNames) {
    return additionals.filter(record =>
        (record.type === 'A' || record.type === 'AAAA') &&
        nsNames.includes(normalizeDnsName(record.name))
    );
}

function getMinimizedQnames(domain) {
    const labels = normalizeDnsName(domain).split('.');
    return labels.map((_, index) => labels.slice(index).join('.')).reverse();
}

async function getZoneApex(domain, dnsResponseCache, dependencies = {}) {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = dependencies.queryDirectlyUDP || queryDirectlyUDP;
    let currentNs = 'a.root-servers.net';
    let currentServerIPs = await resolveIPs(currentNs);
    let currentServerNameMap = Object.fromEntries((currentServerIPs || []).map(serverIp => [serverIp, currentNs]));
    let parentNs = '';
    let parentServerIPs = [];
    let parentServerNameMap = {};
    let zoneApex = '';
    let hasCnameOrDname = false;
    let hasAddressRecordWithoutDelegation = false;
    let hasNoDelegationForQname = false;
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
        const referralAddressRecords = getReferralAddressRecords(delegation.additionals, nextNsNames);
        const inBailiwickGlueRecords = referralAddressRecords.filter(record => isInBailiwickGlue(record, nextNsNames, delegation.nextZone));
        const inBailiwickGlueNames = new Set(inBailiwickGlueRecords.map(record => normalizeDnsName(record.name)));
        const referralAddressNames = new Set(referralAddressRecords.map(record => normalizeDnsName(record.name)));
        const glueIPs = inBailiwickGlueRecords.map(record => record.data);
        const referralAddressIPs = referralAddressRecords.map(record => record.data);
        const nextServerNameMap = {};
        referralAddressIPs.forEach(serverIp => {
            const glueRecord = delegation.additionals.find(record => record.data === serverIp && nextNsNames.includes(normalizeDnsName(record.name)));
            if (glueRecord && !nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = normalizeDnsName(glueRecord.name);
        });
        // in-bailiwick glue が無い NS 名は、他の NS 名が glue を持っていても個別に名前解決を試みる。
        const nsNamesNeedingResolution = nextNsNames.filter(nsName => !referralAddressNames.has(nsName));
        const resolvedIPsByName = nsNamesNeedingResolution.length > 0
            ? await Promise.all(nsNamesNeedingResolution.map(async nsName => ({
                nsName,
                ips: await resolveIPs(nsName)
            })))
            : [];
        resolvedIPsByName.forEach(({ nsName, ips }) => {
            (ips || []).filter(Boolean).forEach(serverIp => {
                if (!nextServerNameMap[serverIp]) nextServerNameMap[serverIp] = nsName;
            });
        });
        const nextServerIPs = [...new Set([...referralAddressIPs, ...resolvedIPsByName.flatMap(({ ips }) => (ips || []).filter(Boolean))])];
        const unresolvedNsNames = resolvedIPsByName
            .filter(({ ips }) => !ips || ips.length === 0)
            .map(({ nsName }) => nsName);

        const delegationLog = pushExplorationLog('FOLLOW_DELEGATION', `${qname} に対して ${nextNsNames.join(', ')} を示しました。 (${delegation.serverIp})`, currentNs, currentParent, {
            parentLogId: currentParentLogId,
            nextServer: nextNsNames,
            glueIPs,
            rfc9471: summarizeRfc9471Referral(delegation.nsRecords, delegation.additionals),
            nsResolutionWarning: unresolvedNsNames.length > 0 ? { names: unresolvedNsNames } : null
        });

        if (nextServerIPs.length === 0) {
            pushExplorationLog(
                'LAME_DELEGATION_NO_NS_IP_ADDRESS',
                `委任先 NS レコード (${nextNsNames.join(', ')}) の IP アドレスを取得できないため、ゾーン頂点を確認できません。`,
                currentNs,
                currentParent
            );
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
        lastDelegatedZone = delegation.nextZone;
        lastDelegatedOrder = qnameIndex;
        qnameIndex++;

        // 最終入力名への委任がある場合は、委任先で CNAME/DNAME か確認する。
        if (qnameIndex >= minimizedQnames.length) {
            for (const nextServerIp of currentServerIPs) {
                const childResponse = await queryUDP(qname, nextServerIp, dnsResponseCache, 'NS');
                if (childResponse.error) continue;

                const childCnameRecord = (childResponse.answers || []).find(record => record.type === 'CNAME');
                const childDnameRecord = (childResponse.answers || []).find(record => record.type === 'DNAME');
                if (childCnameRecord || childDnameRecord) {
                    const detail = childCnameRecord
                        ? `入力名は CNAME (${normalizeDnsName(childCnameRecord.name)} -> ${normalizeDnsName(childCnameRecord.data)}) です。CNAME の委任先は追跡せず、ゾーン頂点としての委任検査を終了します。 (${nextServerIp})`
                        : `回答に DNAME が含まれており、ゾーン頂点を確定できませんでした。 (${nextServerIp})`;
                    pushExplorationLog(childCnameRecord ? 'CNAME_FOUND' : 'DNAME_FOUND', detail, currentNs, currentNs, { parentLogId: delegationLog.id });
                    hasCnameOrDname = true;
                    break;
                }
            }
        }
    }

    if (!hasCnameOrDname && lastColocatedDelegation && lastColocatedDelegation.order > lastDelegatedOrder) {
        zoneApex = lastColocatedDelegation.zoneApex;
        parentDelegationUnavailable = true;
        pushExplorationLog('ZONE_APEX_FOUND', `ゾーン頂点を確定: ${zoneApex}。親ゾーンと同じ権威サーバーで提供されているため、親側の委任情報は使用できません。`, currentNs, parentNs || null, { parentLogId: colocatedParentLogId });
    } else if (!hasCnameOrDname && lastDelegatedZone) {
        zoneApex = lastDelegatedZone;
        pushExplorationLog('ZONE_APEX_FOUND', `ゾーン頂点を確定: ${zoneApex}。親ゾーンの委任情報を使用して検査します。`, currentNs, parentNs || null);
    }

    return {
        currentNs: currentNs,
        parentNs: parentNs,
        parentServerIPs: parentServerIPs,
        parentServerNameMap: parentServerNameMap,
        zoneApex: zoneApex,
        hasCnameOrDname,
        hasAddressRecordWithoutDelegation,
        hasNoDelegationForQname,
        parentDelegationUnavailable: parentDelegationUnavailable,
        colocatedDelegation: lastColocatedDelegation,
        explorationLogs: explorationLogs,
        errorLogs: explorationLogs
    };
}

async function traceDomain(domain, servers, dnsResponseCache, parentIP = null, currentDepth = 1, expectedNSList = [], parentGlueMap = {}, dependencies = {}, serverNameMap = {}) {
    const resolveIPs = dependencies.resolveServerIPs || resolveServerIPs;
    const queryUDP = dependencies.queryDirectlyUDP || queryDirectlyUDP;
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

    for (const serverIp of servers) {
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
            continue; 
        }

        if (res.error === 'SEND_ERROR' || res.error === 'SOCKET_ERROR' || res.error === 'DECODE_ERROR') {
            logEntry.status = 'NETWORK_ERROR';
            logEntry.detail = `エラー: ${res.detail}`;
            results.push(logEntry);
            continue;
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
            continue;
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
                const childIPs = await resolveIPs(currentNSName);
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
            continue;
        }

        const nsRecords = authorities.filter(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
        if (nsRecords.length > 0) {
            logEntry.status = 'DELEGATED';
            logEntry.detail = `AUTHORITY SECTION に ${nsRecords.length} 個の NS レコード。IP アドレスを以下に列挙。${cacheNote}`;
            results.push(logEntry);

            const currentNSNames = nsRecords.map(r => normalizeDnsName(r.data));
            const delegatedZone = normalizeDnsName(nsRecords[0].name);
            logEntry.rfc9471 = summarizeRfc9471Referral(nsRecords, additionals, res.retryFrom);

            let nextGlueMap = {};
            let nextServerIPs = [];
            let nextServerNameMap = {};

            for (const ns of nsRecords) {
                const nsKey = normalizeDnsName(ns.data);
                nextGlueMap[nsKey] = [];

                const matchedAddressRecords = getReferralAddressRecords(additionals, [nsKey]);
                const matchedGlues = matchedAddressRecords.filter(record => isInBailiwickGlue(record, [nsKey], delegatedZone));
                if (matchedAddressRecords.length > 0) {
                    // 本来の意味での Glueをリストに登録
                    matchedGlues.forEach(g => {
                        nextGlueMap[nsKey].push(g.data);
                    });
                    matchedAddressRecords.forEach(g => {
                        nextServerIPs.push(g.data);
                        if (!nextServerNameMap[g.data]) nextServerNameMap[g.data] = nsKey;
                    });
                } else {
                    // 本来の意味での Glue が無かった場合に、親が持つ子情報から IP アドレスを取得してリストに登録
                    const resolvedIPs = await resolveIPs(ns.data);
                    if (resolvedIPs) {
                        resolvedIPs.forEach(ip => {
                            nextServerIPs.push(ip);
                            if (!nextServerNameMap[ip]) nextServerNameMap[ip] = nsKey;
                        });
                    }
                }
            }

            nextServerIPs = [...new Set(nextServerIPs)];

            if (nextServerIPs.length > 0) {
                const childResults = await traceDomain(domain, nextServerIPs, dnsResponseCache, serverIp, currentDepth + 1, currentNSNames, nextGlueMap, dependencies, nextServerNameMap);
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
    }
    return results;
}

app.post('/api/trace', async (req, res) => {
    const domain = normalizeUserDomain(req.body?.domain);
    if (!domain) {
        return res.status(400).json({ error: 'ドメイン名を入力してください' });
    }

    const dnsResponseCache = new Map();

    try {
        let zoneApexTimer;
        const zoneApexInfo = await Promise.race([
            getZoneApex(domain, dnsResponseCache),
            new Promise(resolve => {
                zoneApexTimer = setTimeout(() => resolve({
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
                }), 30000);
            })
        ]);
        clearTimeout(zoneApexTimer);
        const explorationLog = zoneApexInfo.explorationLogs || zoneApexInfo.errorLogs || [];

        let traceLog = [];
        if (!zoneApexInfo.timedOut && zoneApexInfo.zoneApex !== '' && !zoneApexInfo.parentDelegationUnavailable) {
            const serverList = zoneApexInfo.parentServerIPs.length > 0
                ? zoneApexInfo.parentServerIPs
                : await resolveServerIPs('a.root-servers.net');
            const serverNameMap = zoneApexInfo.parentServerNameMap || Object.fromEntries(serverList.map(serverIp => [serverIp, zoneApexInfo.parentNs || 'a.root-servers.net']));
            traceLog = await traceDomain(zoneApexInfo.zoneApex, serverList, dnsResponseCache, null, 1, [], {}, {}, serverNameMap);
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
        res.status(500).json({ success: false, error: error.message });
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
