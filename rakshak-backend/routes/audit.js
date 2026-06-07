import express from "express";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, getClientIp } from "../middleware/auth.js";
import { generateTxHash, logDataAccessOnChain } from "../services/blockchain.js";
import { checkAndFlagAnomaly } from "../services/anomalyDetection.js";

const router = express.Router();

router.get("/audit-logs", authenticateToken, async (req, res) => {
  const { limit = 50, page = 1 } = req.query;
  const skip = (Number(page) - 1) * Number(limit);

  const [logs, total] = await Promise.all([
    AuditLog.find().sort({ created_at: -1 }).skip(skip).limit(Number(limit)).lean(),
    AuditLog.countDocuments(),
  ]);

  return res.json({ logs, total, page: Number(page), limit: Number(limit) });
});

router.post("/log-access", authenticateToken, async (req, res) => {
  const { dataType, action } = req.body;
  const dataAccessed = dataType || req.body.dataAccessed || "unknown";
  const logAction = action || "RECORD_ACCESS";
  const ipAddress = getClientIp(req);

  if (!dataAccessed) {
    return res.status(400).json({ error: "dataType is required" });
  }

  try {
    const chainTx = await logDataAccessOnChain({
      idNumber: req.user.idNumber,
      hospitalName: req.user.hospitalName,
      post: req.user.post,
      dataType: dataAccessed,
    });

    const txHash =
      chainTx ||
      generateTxHash({
        staffId: req.user.idNumber,
        action: logAction,
        data: dataAccessed,
        ipAddress,
      });

    await AuditLog.create({
      staff_id: req.user.idNumber,
      action: logAction,
      details: {
        hospital_name: req.user.hospitalName,
        post: req.user.post,
        data_accessed: dataAccessed,
      },
      ip_address: ipAddress,
      tx_hash: txHash,
    });

    const { anomalyDetected } = await checkAndFlagAnomaly({
      staffId: req.user.idNumber,
      hospitalName: req.user.hospitalName,
      post: req.user.post,
      ipAddress,
    });

    return res.json({ success: true, tx_hash: txHash, anomalyDetected });
  } catch (err) {
    console.error("Log access error:", err);
    return res.status(500).json({ error: "Failed to log data access" });
  }
});

export default router;
