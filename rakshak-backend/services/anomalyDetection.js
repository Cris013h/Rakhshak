import { AuditLog } from "../models/AuditLog.js";
import { generateTxHash, logSuspiciousActivityOnChain } from "./blockchain.js";

export const ANOMALY_THRESHOLD = 20;
export const ANOMALY_WINDOW_MS = 10 * 60 * 1000;

const recentAnomalies = new Set();

export async function checkAndFlagAnomaly({ staffId, hospitalName, post, ipAddress }) {
  const windowStart = new Date(Date.now() - ANOMALY_WINDOW_MS);
  const accessCount = await AuditLog.countDocuments({
    staff_id: staffId,
    action: "RECORD_ACCESS",
    created_at: { $gte: windowStart },
  });

  if (accessCount <= ANOMALY_THRESHOLD) {
    return { anomalyDetected: false, accessCount };
  }

  const anomalyKey = `${staffId}-${Math.floor(Date.now() / ANOMALY_WINDOW_MS)}`;
  if (recentAnomalies.has(anomalyKey)) {
    return { anomalyDetected: false, accessCount };
  }

  recentAnomalies.add(anomalyKey);
  setTimeout(() => recentAnomalies.delete(anomalyKey), ANOMALY_WINDOW_MS);

  const chainTx = await logSuspiciousActivityOnChain({
    idNumber: staffId,
    activityType: `Excessive access: ${accessCount} records in 10 minutes`,
  });

  const anomalyTxHash =
    chainTx ||
    generateTxHash({
      staffId,
      action: "ANOMALY",
      accessCount,
      ipAddress,
    });

  await AuditLog.create({
    staff_id: staffId,
    action: "ANOMALY",
    details: {
      hospital_name: hospitalName,
      post,
      records_accessed: accessCount,
      window_minutes: 10,
      ip_address: ipAddress,
    },
    ip_address: ipAddress,
    tx_hash: anomalyTxHash,
  });

  return { anomalyDetected: true, accessCount, txHash: anomalyTxHash };
}

export async function getRecentAnomalies(limit = 20) {
  return AuditLog.find({ action: "ANOMALY" })
    .sort({ created_at: -1 })
    .limit(limit)
    .lean();
}
