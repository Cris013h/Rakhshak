import { FirewallLog } from "../models/FirewallLog.js";
import { logDataAccessOnChain } from "../services/blockchain.js";
import { getClientIp } from "./auth.js";

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_BLOCK_MS = 5 * 60 * 1000;
const FLOOD_THRESHOLD = 30;
const BRUTE_FORCE_THRESHOLD = 10;

const SQL_PATTERNS = [
  /\bselect\b/i,
  /\bdrop\b/i,
  /\binsert\b/i,
  /--/,
  /;/,
];

const XSS_PATTERNS = [
  /<script>/i,
  /javascript:/i,
  /onerror\s*=/i,
];

const ipRequestTimestamps = new Map();
const rateLimitBlocks = new Map();
const blocklist = new Map();
const failedLoginCounts = new Map();
const ipAttemptCounts = new Map();

const trafficBuckets = [];
const TRAFFIC_BUCKET_MS = 60 * 1000;
const MAX_TRAFFIC_BUCKETS = 30;

function getMinuteKey(date = new Date()) {
  return `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;
}

function getCurrentTrafficBucket() {
  const now = Date.now();
  const key = getMinuteKey(new Date(now));
  let bucket = trafficBuckets.find((b) => b.key === key && now - b.startedAt < TRAFFIC_BUCKET_MS);

  if (!bucket) {
    bucket = {
      key,
      label: key,
      time: key,
      requests: 0,
      blocked: 0,
      startedAt: now,
    };
    trafficBuckets.push(bucket);
    if (trafficBuckets.length > MAX_TRAFFIC_BUCKETS) {
      trafficBuckets.shift();
    }
  }

  return bucket;
}

function recordTraffic(blocked = false) {
  const bucket = getCurrentTrafficBucket();
  bucket.requests += 1;
  if (blocked) {
    bucket.blocked += 1;
  }
}

function pruneOldTimestamps(ip) {
  const now = Date.now();
  const timestamps = ipRequestTimestamps.get(ip) || [];
  const pruned = timestamps.filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);
  ipRequestTimestamps.set(ip, pruned);
  return pruned;
}

function scanForPatterns(value, patterns) {
  if (value == null) return false;
  const str = typeof value === "string" ? value : JSON.stringify(value);
  return patterns.some((pattern) => pattern.test(str));
}

function scanRequestBody(req) {
  const parts = [
    req.url,
    JSON.stringify(req.query || {}),
    JSON.stringify(req.body || {}),
    JSON.stringify(req.params || {}),
  ];

  for (const part of parts) {
    if (scanForPatterns(part, SQL_PATTERNS)) return "SQL_INJECTION_ATTEMPT";
    if (scanForPatterns(part, XSS_PATTERNS)) return "XSS_ATTEMPT";
  }

  return null;
}

async function logBlockToDb({ ip, attackType, requestDetails }) {
  const attempts = (ipAttemptCounts.get(ip) || 0) + 1;
  ipAttemptCounts.set(ip, attempts);

  const txHash = await logDataAccessOnChain({
    idNumber: ip,
    hospitalName: "FIREWALL",
    post: "SYSTEM",
    dataType: attackType,
  });

  await FirewallLog.create({
    ip,
    attackType,
    timestamp: new Date(),
    requestDetails,
    attempts,
    status: "Blocked",
    tx_hash: txHash || "",
  });
}

async function addToBlocklist(ip, attackType, requestDetails) {
  if (blocklist.has(ip)) return;

  blocklist.set(ip, {
    attackType,
    blockedAt: Date.now(),
    attempts: ipAttemptCounts.get(ip) || 1,
  });

  try {
    await logBlockToDb({ ip, attackType, requestDetails });
  } catch (err) {
    console.error("Firewall log failed:", err.message);
  }
}

function isRateLimited(ip) {
  const blockedUntil = rateLimitBlocks.get(ip);
  if (!blockedUntil) return false;

  if (Date.now() >= blockedUntil) {
    rateLimitBlocks.delete(ip);
    return false;
  }

  return true;
}

function applyRateLimitBlock(ip) {
  rateLimitBlocks.set(ip, Date.now() + RATE_LIMIT_BLOCK_MS);
}

async function checkFloodAttack(ip, requestDetails) {
  const timestamps = pruneOldTimestamps(ip);
  if (timestamps.length > FLOOD_THRESHOLD) {
    await addToBlocklist(ip, "FLOOD_ATTACK", requestDetails);
    return true;
  }
  return false;
}

function trackRequest(ip) {
  const timestamps = pruneOldTimestamps(ip);
  timestamps.push(Date.now());
  ipRequestTimestamps.set(ip, timestamps);
}

function trackFailedLogin(ip) {
  const count = (failedLoginCounts.get(ip) || 0) + 1;
  failedLoginCounts.set(ip, count);
  return count;
}

export async function unblockIp(ip) {
  blocklist.delete(ip);
  rateLimitBlocks.delete(ip);
  ipRequestTimestamps.delete(ip);
  failedLoginCounts.delete(ip);
  ipAttemptCounts.delete(ip);

  await FirewallLog.updateMany(
    { ip, status: "Blocked" },
    { $set: { status: "Unblocked" } }
  );
}

export function getTrafficData() {
  return trafficBuckets.map(({ label, time, requests, blocked }) => ({
    label,
    time,
    requests,
    blocked,
  }));
}

export async function getFirewallStats() {
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);

  const [blockedToday, activeBlocked, attackAgg] = await Promise.all([
    FirewallLog.countDocuments({
      timestamp: { $gte: todayStart },
    }),
    FirewallLog.distinct("ip", { status: "Blocked" }),
    FirewallLog.aggregate([
      { $match: { timestamp: { $gte: todayStart } } },
      { $group: { _id: "$attackType", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 },
    ]),
  ]);

  return {
    totalAttacksBlockedToday: blockedToday,
    activeBlockedIps: activeBlocked.length,
    mostCommonAttackType: attackAgg[0]?._id || "None",
  };
}

export async function getFirewallLogs() {
  const logs = await FirewallLog.aggregate([
    { $sort: { timestamp: -1 } },
    {
      $group: {
        _id: "$ip",
        ip: { $first: "$ip" },
        attackType: { $first: "$attackType" },
        timestamp: { $first: "$timestamp" },
        attempts: { $max: "$attempts" },
        status: { $first: "$status" },
        requestDetails: { $first: "$requestDetails" },
      },
    },
    { $sort: { timestamp: -1 } },
    { $limit: 100 },
  ]);

  return logs;
}

export function firewallMiddleware() {
  return async (req, res, next) => {
    const ip = getClientIp(req) || req.socket?.remoteAddress || "unknown";
    const requestDetails = {
      method: req.method,
      path: req.originalUrl || req.url,
      body: req.body,
      query: req.query,
    };

    const patternAttack = scanRequestBody(req);
    if (patternAttack) {
      recordTraffic(true);
      await addToBlocklist(ip, patternAttack, requestDetails);
      return res.status(403).json({
        error: "Your IP has been blocked due to suspicious activity.",
        attackType: patternAttack,
      });
    }

    trackRequest(ip);

    const flooded = await checkFloodAttack(ip, requestDetails);
    if (flooded) {
      recordTraffic(true);
      return res.status(403).json({
        error: "Your IP has been blocked due to suspicious activity.",
        attackType: "FLOOD_ATTACK",
      });
    }

    if (isRateLimited(ip)) {
      recordTraffic(true);
      return res.status(429).json({
        error: "Too many requests from this IP. You have been temporarily blocked.",
      });
    }

    const recentCount = pruneOldTimestamps(ip).length;
    if (recentCount > RATE_LIMIT_MAX) {
      recordTraffic(true);
      applyRateLimitBlock(ip);
      try {
        await logBlockToDb({
          ip,
          attackType: "RATE_LIMIT_EXCEEDED",
          requestDetails,
        });
      } catch (err) {
        console.error("Rate limit log failed:", err.message);
      }
      return res.status(429).json({
        error: "Too many requests from this IP. You have been temporarily blocked.",
      });
    }

    if (blocklist.has(ip)) {
      recordTraffic(true);
      return res.status(403).json({
        error: "Your IP has been blocked due to suspicious activity.",
        attackType: blocklist.get(ip).attackType,
      });
    }

    recordTraffic(false);

    res.on("finish", async () => {
      const requestPath = (req.originalUrl || req.url || "").split("?")[0];
      if (requestPath.endsWith("/login") && req.method === "POST") {
        const isFailed = res.statusCode === 401 || res.statusCode === 400 || res.statusCode === 423;
        if (isFailed) {
          const failCount = trackFailedLogin(ip);
          if (failCount >= BRUTE_FORCE_THRESHOLD && !blocklist.has(ip)) {
            await addToBlocklist(ip, "BRUTE_FORCE_ATTACK", {
              ...requestDetails,
              failedLoginCount: failCount,
            });
          }
        } else if (res.statusCode === 200) {
          failedLoginCounts.delete(ip);
        }
      }
    });

    next();
  };
}
