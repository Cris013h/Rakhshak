import express from "express";
import { Prescription } from "../models/Prescription.js";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { generateTxHash } from "../services/blockchain.js";

const router = express.Router();

router.use(authenticateToken, requireRole("Pharmacist"));

router.get("/prescriptions", async (req, res) => {
  const prescriptions = await Prescription.find()
    .sort({ created_at: -1 })
    .lean();
  return res.json({ prescriptions });
});

router.post("/prescriptions/:id/process", async (req, res) => {
  const ipAddress = getClientIp(req);
  const rx = await Prescription.findByIdAndUpdate(
    req.params.id,
    { status: "FILLED" },
    { new: true }
  );

  if (!rx) {
    return res.status(404).json({ error: "Prescription not found" });
  }

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "RECORD_ACCESS",
    prescriptionId: rx._id.toString(),
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "RECORD_ACCESS",
    details: {
      data_accessed: `Processed prescription: ${rx.medication} for ${rx.patient_name}`,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ prescription: rx, tx_hash: txHash });
});

export default router;
