import express from "express";
import { AuditLog } from "../models/AuditLog.js";
import { Staff } from "../models/Staff.js";
import { Session } from "../models/Session.js";
import { authenticateToken, requireAdmin, getClientIp, getActiveSessionCount } from "../middleware/auth.js";
import { generateTxHash } from "../services/blockchain.js";
import {
  getFirewallLogs,
  getFirewallStats,
  getTrafficData,
  unblockIp,
} from "../middleware/firewall.js";

const router = express.Router();

router.use(authenticateToken, requireAdmin);

router.get("/audit-logs", async (req, res) => {
  const { startDate, endDate, post, action, idNumber, limit = 200, page = 1 } = req.query;
  const filter = {};

  if (startDate || endDate) {
    filter.created_at = {};
    if (startDate) filter.created_at.$gte = new Date(startDate);
    if (endDate) filter.created_at.$lte = new Date(endDate);
  }
  if (post) filter["details.post"] = post;
  if (action) filter.action = action;
  if (idNumber) filter.staff_id = idNumber.toUpperCase();

  const skip = (Number(page) - 1) * Number(limit);
  const [logs, total] = await Promise.all([
    AuditLog.find(filter).sort({ created_at: -1 }).skip(skip).limit(Number(limit)).lean(),
    AuditLog.countDocuments(filter),
  ]);

  return res.json({ logs, total, page: Number(page), limit: Number(limit) });
});

router.get("/stats", async (req, res) => {
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);

  const [totalLoginsToday, failedAttempts, anomalies, activeSessions] = await Promise.all([
    AuditLog.countDocuments({
      action: "LOGIN",
      "details.success": true,
      created_at: { $gte: todayStart },
    }),
    AuditLog.countDocuments({
      action: "LOGIN",
      "details.success": false,
      created_at: { $gte: todayStart },
    }),
    AuditLog.countDocuments({
      action: "ANOMALY",
      created_at: { $gte: todayStart },
    }),
    getActiveSessionCount(),
  ]);

  return res.json({ totalLoginsToday, failedAttempts, activeSessions, anomalies });
});

router.get("/anomalies", async (req, res) => {
  const anomalies = await AuditLog.find({ action: "ANOMALY" })
    .sort({ created_at: -1 })
    .limit(20)
    .lean();
  return res.json({ anomalies });
});

router.get("/locked-accounts", async (req, res) => {
  const locked = await Staff.find({ locked_until: { $gt: new Date() } })
    .select("id_number hospital_name post locked_until failed_login_attempts")
    .sort({ locked_until: -1 })
    .lean();
  return res.json({ locked });
});

router.post("/unlock/:idNumber", async (req, res) => {
  const idNumber = req.params.idNumber.toUpperCase();
  const ipAddress = getClientIp(req);

  const result = await Staff.findOneAndUpdate(
    { id_number: idNumber },
    { locked_until: null, failed_login_attempts: 0 },
    { new: true }
  );

  if (!result) {
    return res.status(404).json({ error: "Staff not found" });
  }

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "UNLOCK",
    target: idNumber,
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "UNLOCK",
    details: {
      unlocked_account: idNumber,
      hospital_name: req.user.hospitalName,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ message: `Account ${idNumber} unlocked` });
});

router.get("/firewall/logs", async (_req, res) => {
  const logs = await getFirewallLogs();
  return res.json({ logs });
});

router.get("/firewall/stats", async (_req, res) => {
  const stats = await getFirewallStats();
  return res.json(stats);
});

router.get("/firewall/traffic", async (_req, res) => {
  const traffic = getTrafficData();
  return res.json({ traffic });
});

router.post("/firewall/unblock/:ip", async (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  await unblockIp(ip);
  return res.json({ message: `IP ${ip} has been unblocked` });
});

router.get("/registered-users", async (req, res) => {
  const users = await Staff.find()
    .select("id_number hospital_name post ward locked_until failed_login_attempts created_at")
    .sort({ created_at: 1 })
    .lean();

  const enriched = users.map((u) => ({
    idNumber: u.id_number,
    hospitalName: u.hospital_name,
    post: u.post,
    ward: u.ward,
    locked: u.locked_until ? u.locked_until > new Date() : false,
    lockedUntil: u.locked_until,
  }));

  return res.json({ users: enriched });
});

export default router;
