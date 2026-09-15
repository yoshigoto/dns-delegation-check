import { getZoneApex } from './dns-delegation-check.js';

const result = await getZoneApex('tkix.net', new Map());
const logs = result.explorationLogs ?? [];
const warnings = logs.filter((entry) => Boolean(entry.nsResolutionWarning));
const followIds = new Set(
  logs.filter((entry) => entry.type === 'FOLLOW_DELEGATION').map((entry) => entry.id)
);
const nestedWarningLogs = warnings.filter((entry) => followIds.has(entry.parentLogId));
console.log(JSON.stringify(warnings, null, 2));
console.log(`nsResolutionWarning entries: ${warnings.length}`);
console.log(`none nested under FOLLOW_DELEGATION: ${nestedWarningLogs.length === 0}`);
if (nestedWarningLogs.length > 0) {
  console.log(`nested parentLogIds: ${JSON.stringify(nestedWarningLogs.map((entry) => entry.parentLogId))}`);
  process.exitCode = 1;
}
