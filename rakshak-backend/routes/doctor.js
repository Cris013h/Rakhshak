import express from "express";
import { Patient } from "../models/Patient.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { AuditLog } from "../models/AuditLog.js";
import { generateTxHash } from "../services/blockchain.js";

const router = express.Router();

router.use(authenticateToken, requireRole("Doctor"));

router.get("/patients", async (req, res) => {
  const patients = await Patient.find({ assigned_doctor_id: req.user.idNumber }).lean();
  const decrypted = Patient.decryptMany(patients);
  decrypted.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
  return res.json({ patients: decrypted });
});

router.get("/patients/:id", async (req, res) => {
  const ipAddress = getClientIp(req);
  const patient = await Patient.findById(req.params.id).lean();

  if (!patient) {
    return res.status(404).json({ error: "Patient not found" });
  }

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "RECORD_ACCESS",
    patientId: patient._id.toString(),
    ipAddress,
  });

  const decrypted = Patient.decryptDocument(patient);

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "RECORD_ACCESS",
    details: {
      patient_id: patient._id.toString(),
      patient_name: decrypted.name,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
      data_accessed: `Patient Record: ${decrypted.name}`,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ patient: decrypted, tx_hash: txHash });
});

export default router;
