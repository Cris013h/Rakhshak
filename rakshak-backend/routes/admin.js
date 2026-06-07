import express from "express";
import { AuditLog } from "../models/AuditLog.js";
import { Staff } from "../models/Staff.js";
import { PreRegisteredStaff } from "../models/PreRegisteredStaff.js";
import { MedicalRecord } from "../models/MedicalRecord.js";
import { authenticateToken, requireAdmin, getClientIp, getActiveSessionCount } from "../middleware/auth.js";
import { generateTxHash, preRegisterStaffOnChain, checkPreRegisteredOnChain } from "../services/blockchain.js";
import { sendWelcomeEmail } from "../services/emailService.js";
import { verifySignature } from "../services/signatureService.js";
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

router.get("/stats", async (_req, res) => {
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const firewallStats = await getFirewallStats();

  const [totalLoginsToday, failedAttempts, anomalies, activeSessions] = await Promise.all([
    AuditLog.countDocuments({ action: "LOGIN", "details.success": true, created_at: { $gte: todayStart } }),
    AuditLog.countDocuments({ action: { $in: ["LOGIN", "LOGIN_STEP1", "FAILED_OTP"] }, "details.success": false, created_at: { $gte: todayStart } }),
    AuditLog.countDocuments({ action: "ANOMALY", created_at: { $gte: todayStart } }),
    getActiveSessionCount(),
  ]);

  return res.json({
    totalLoginsToday,
    failedAttempts,
    activeSessions,
    anomalies,
    blockedIPs: firewallStats?.activeBlockedIps ?? 0,
  });
});

router.get("/encryption-status", async (_req, res) => {
  const { getPublicKey } = await import("../services/rsaService.js");
  const { Patient } = await import("../models/Patient.js");
  const patientCount = await Patient.countDocuments();

  return res.json({
    rsa: { algorithm: "RSA-2048", status: "active", publicKeyAvailable: Boolean(getPublicKey()) },
    aes: {
      algorithm: "AES-256-CBC",
      status: process.env.AES_SECRET_KEY?.length === 32 ? "active" : "misconfigured",
      keyLength: process.env.AES_SECRET_KEY?.length ?? 0,
    },
    encryptedRecords: patientCount,
    transitEncryption: "RSA-OAEP/PKCS1-v1_5",
    atRestEncryption: "AES-256-CBC with per-record IV",
  });
});

router.get("/anomalies", async (_req, res) => {
  const anomalies = await AuditLog.find({ action: "ANOMALY" }).sort({ created_at: -1 }).limit(20).lean();
  return res.json({ anomalies });
});

router.get("/locked-accounts", async (_req, res) => {
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

  if (!result) return res.status(404).json({ error: "Staff not found" });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "UNLOCK",
    details: { unlocked_account: idNumber },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: req.user.idNumber, action: "UNLOCK", target: idNumber, ipAddress }),
  });

  return res.json({ message: `Account ${idNumber} unlocked` });
});

router.get("/firewall/logs", async (_req, res) => res.json({ logs: await getFirewallLogs() }));
router.get("/firewall/stats", async (_req, res) => res.json(await getFirewallStats()));
router.get("/firewall/traffic", async (_req, res) => res.json({ traffic: getTrafficData() }));
router.post("/firewall/unblock/:ip", async (req, res) => {
  await unblockIp(decodeURIComponent(req.params.ip));
  return res.json({ message: `IP unblocked` });
});

router.get("/registered-users", async (_req, res) => {
  const users = await Staff.find()
    .select("id_number username hospital_name post ward locked_until failed_login_attempts created_at is_active")
    .sort({ created_at: 1 })
    .lean();

  return res.json({
    users: users.map((u) => ({
      idNumber: u.id_number,
      username: u.username,
      hospitalName: u.hospital_name,
      post: u.post,
      ward: u.ward,
      locked: u.locked_until ? u.locked_until > new Date() : false,
      isActive: u.is_active,
    })),
  });
});

router.post("/preregister-staff", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { fullName, idNumber, post, hospitalName, department, email, phone, startDate } = req.body;

  if (!fullName || !idNumber || !post || !email) {
    return res.status(400).json({ error: "Required fields: fullName, idNumber, post, email" });
  }

  const normalizedId = idNumber.trim().toUpperCase();
  const hospital = hospitalName?.trim() || req.user.hospitalName;

  const existing = await PreRegisteredStaff.findOne({ idNumber: normalizedId });
  if (existing) return res.status(409).json({ error: "Staff ID already pre-registered" });

  const existingStaff = await Staff.findOne({ id_number: normalizedId });
  if (existingStaff) return res.status(409).json({ error: "Staff already has an active account" });

  const blockchainTxHash = await preRegisterStaffOnChain({
    fullName: fullName.trim(),
    idNumber: normalizedId,
    post,
    hospitalName: hospital,
    department: department || "",
    email: email.trim(),
  });

  const preReg = await PreRegisteredStaff.create({
    fullName: fullName.trim(),
    idNumber: normalizedId,
    post,
    hospitalName: hospital,
    department: department || "",
    email: email.trim(),
    phone: phone || "",
    startDate: startDate ? new Date(startDate) : new Date(),
    status: "pending",
    registeredBy: req.user.idNumber,
    blockchainTxHash: blockchainTxHash || "",
  });

  await sendWelcomeEmail({
    to: email.trim(),
    fullName: fullName.trim(),
    idNumber: normalizedId,
    post,
    hospitalName: hospital,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "STAFF_PREREGISTERED",
    details: { target: normalizedId, post, email },
    ip_address: ipAddress,
    tx_hash: blockchainTxHash || generateTxHash({ staffId: req.user.idNumber, action: "STAFF_PREREGISTERED", ipAddress }),
  });

  return res.status(201).json({
    success: true,
    idNumber: normalizedId,
    status: "pending",
    message: "Staff pre-registered on blockchain",
  });
});

router.get("/staff-list", async (_req, res) => {
  const staff = await PreRegisteredStaff.find().sort({ registeredAt: -1 }).lean();
  const enriched = await Promise.all(
    staff.map(async (s) => {
      const chainStatus = await checkPreRegisteredOnChain(s.idNumber);
      const activeStaff = await Staff.findOne({ id_number: s.idNumber });
      return {
        ...s,
        blockchainActivated: chainStatus.activated,
        hasAccount: Boolean(activeStaff),
        accountVerified: activeStaff?.is_verified || false,
      };
    })
  );
  return res.json({ staff: enriched });
});

router.post("/resend-welcome-email/:idNumber", async (req, res) => {
  const preReg = await PreRegisteredStaff.findOne({ idNumber: req.params.idNumber.toUpperCase() });
  if (!preReg) return res.status(404).json({ error: "Staff not found" });

  await sendWelcomeEmail({
    to: preReg.email,
    fullName: preReg.fullName,
    idNumber: preReg.idNumber,
    post: preReg.post,
    hospitalName: preReg.hospitalName,
  });

  return res.json({ success: true, message: "Welcome email resent" });
});

router.put("/staff-status/:idNumber", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { status } = req.body;
  const idNumber = req.params.idNumber.toUpperCase();

  if (!["active", "locked", "suspended", "pending"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const preReg = await PreRegisteredStaff.findOneAndUpdate({ idNumber }, { status }, { new: true });
  const staff = await Staff.findOne({ id_number: idNumber });

  if (staff) {
    if (status === "locked") {
      staff.locked_until = new Date(Date.now() + 24 * 60 * 60 * 1000);
      staff.is_active = false;
    } else if (status === "suspended") {
      staff.is_active = false;
    } else if (status === "active") {
      staff.is_active = true;
      staff.locked_until = null;
    }
    await staff.save();
  }

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "STAFF_STATUS_CHANGE",
    details: { target: idNumber, status },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: req.user.idNumber, action: "STAFF_STATUS_CHANGE", ipAddress }),
  });

  return res.json({ success: true, staff: preReg, staffAccount: staff });
});

router.post("/assign-doctor", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { patientId, doctorId } = req.body;

  const { Patient } = await import("../models/Patient.js");
  const patient = await Patient.findOne({ patientId: patientId.toUpperCase() });
  if (!patient) return res.status(404).json({ error: "Patient not found" });

  if (!patient.assignedDoctors) patient.assignedDoctors = [];
  if (!patient.assignedDoctors.includes(doctorId)) {
    patient.assignedDoctors.push(doctorId);
  }
  patient.assigned_doctor_id = doctorId;
  await patient.save();

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "DOCTOR_ASSIGNED",
    details: { patientId, doctorId },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: req.user.idNumber, action: "DOCTOR_ASSIGNED", ipAddress }),
  });

  return res.json({ success: true, patient: Patient.decryptDocument(patient) });
});

router.get("/record-integrity", async (_req, res) => {
  const records = await MedicalRecord.find().sort({ createdAt: -1 }).limit(100);
  const results = [];

  for (const record of records) {
    const doctor = await Staff.findOne({ id_number: record.doctorId });
    const verification = await verifySignature(
      record.doctorId,
      record.encryptedContent,
      record.signature,
      doctor?.rsa_public_key
    );
    results.push({
      recordId: record._id,
      patientId: record.patientId,
      doctorId: record.doctorId,
      recordType: record.recordType,
      signedAt: record.signedAt,
      verificationStatus: verification.verified ? "verified" : "tampered",
      blockchainTxHash: record.blockchainTxHash,
    });
  }

  return res.json({ records: results });
});

export default router;
