import express from "express";
import { Patient } from "../models/Patient.js";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { generateTxHash, logDataAccessOnChain } from "../services/blockchain.js";
import { checkAndFlagAnomaly } from "../services/anomalyDetection.js";

const router = express.Router();

router.use(authenticateToken, requireRole("Doctor", "Admin", "Nurse", "Receptionist"));

async function logPatientAccess(req, patient, action) {
  const ipAddress = getClientIp(req);
  const decrypted = Patient.decryptDocument(patient);
  const patientId = patient._id.toString();

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action,
    patientId,
    ipAddress,
  });

  let onChainHash = null;
  if (action === "RECORD_ACCESS") {
    onChainHash = await logDataAccessOnChain({
      idNumber: req.user.idNumber,
      hospitalName: req.user.hospitalName,
      post: req.user.post,
      dataType: `Patient Record: ${decrypted.name}`,
    });
  }

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action,
    details: {
      patient_id: patientId,
      patient_name: decrypted.name,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
      data_accessed: `Patient Record: ${decrypted.name}`,
    },
    ip_address: ipAddress,
    tx_hash: onChainHash || txHash,
  });

  await checkAndFlagAnomaly({
    staffId: req.user.idNumber,
    hospitalName: req.user.hospitalName,
    post: req.user.post,
    ipAddress,
  });

  return onChainHash || txHash;
}

function canAccessPatient(req, patient) {
  const post = req.user.post;
  if (post === "Admin") return true;
  if (post === "Doctor") return patient.assigned_doctor_id === req.user.idNumber;
  if (post === "Nurse") return patient.ward === (req.user.ward || "Ward A");
  if (post === "Receptionist") return true;
  return false;
}

router.post("/create", requireRole("Doctor", "Admin", "Receptionist"), async (req, res) => {
  try {
    const {
      name,
      dateOfBirth,
      age,
      ward,
      assigned_doctor_id,
      diagnosis,
      prescription,
      medicalHistory,
      insuranceNumber,
      address,
      phoneNumber,
      emergencyContact,
      condition,
      status,
      medical_notes,
    } = req.body;

    if (!name || age === undefined || !ward) {
      return res.status(400).json({ error: "name, age, and ward are required" });
    }

    const patient = await Patient.create({
      name,
      dateOfBirth: dateOfBirth || "",
      age,
      ward,
      assigned_doctor_id: assigned_doctor_id || req.user.idNumber,
      diagnosis: diagnosis || condition || "",
      prescription: prescription || "",
      medicalHistory: medicalHistory || medical_notes || "",
      insuranceNumber: insuranceNumber || "",
      address: address || "",
      phoneNumber: phoneNumber || "",
      emergencyContact: emergencyContact || "",
      condition: condition || diagnosis || "",
      status: status || "Stable",
      medical_notes: medical_notes || medicalHistory || "",
    });

    const txHash = await logPatientAccess(req, patient, "PATIENT_CREATE");

    return res.status(201).json({
      patient: Patient.decryptDocument(patient),
      tx_hash: txHash,
    });
  } catch (err) {
    console.error("Create patient error:", err);
    return res.status(500).json({ error: "Failed to create patient" });
  }
});

router.get("/", async (req, res) => {
  try {
    let filter = {};

    if (req.user.post === "Doctor") {
      filter = { assigned_doctor_id: req.user.idNumber };
    } else if (req.user.post === "Nurse") {
      filter = { ward: req.user.ward || "Ward A" };
    }

    const patients = await Patient.find(filter).lean();
    const decrypted = Patient.decryptMany(patients);

    decrypted.sort((a, b) => (a.name || "").localeCompare(b.name || ""));

    const txHash = generateTxHash({
      staffId: req.user.idNumber,
      action: "RECORD_ACCESS",
      dataType: "Patient List",
      ipAddress: getClientIp(req),
      count: decrypted.length,
    });

    await AuditLog.create({
      staff_id: req.user.idNumber,
      action: "RECORD_ACCESS",
      details: {
        hospital_name: req.user.hospitalName,
        post: req.user.post,
        data_accessed: `Patient List (${decrypted.length} records)`,
      },
      ip_address: getClientIp(req),
      tx_hash: txHash,
    });

    return res.json({ patients: decrypted, tx_hash: txHash });
  } catch (err) {
    console.error("List patients error:", err);
    return res.status(500).json({ error: "Failed to fetch patients" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ error: "Patient not found" });
    }

    if (!canAccessPatient(req, patient)) {
      return res.status(403).json({ error: "Access denied to this patient record" });
    }

    const txHash = await logPatientAccess(req, patient, "RECORD_ACCESS");

    return res.json({
      patient: Patient.decryptDocument(patient),
      tx_hash: txHash,
    });
  } catch (err) {
    console.error("Get patient error:", err);
    return res.status(500).json({ error: "Failed to fetch patient" });
  }
});

router.put("/:id", requireRole("Doctor", "Admin"), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) {
      return res.status(404).json({ error: "Patient not found" });
    }

    if (!canAccessPatient(req, patient)) {
      return res.status(403).json({ error: "Access denied to this patient record" });
    }

    const updatable = [
      "name",
      "dateOfBirth",
      "age",
      "ward",
      "assigned_doctor_id",
      "diagnosis",
      "prescription",
      "medicalHistory",
      "insuranceNumber",
      "address",
      "phoneNumber",
      "emergencyContact",
      "condition",
      "status",
      "medical_notes",
    ];

    for (const field of updatable) {
      if (req.body[field] !== undefined) {
        patient[field] = req.body[field];
      }
    }

    if (req.body.diagnosis !== undefined) {
      patient.condition = req.body.diagnosis;
    }
    if (req.body.medicalHistory !== undefined) {
      patient.medical_notes = req.body.medicalHistory;
    }

    await patient.save();

    const txHash = await logPatientAccess(req, patient, "PATIENT_UPDATE");

    return res.json({
      patient: Patient.decryptDocument(patient),
      tx_hash: txHash,
    });
  } catch (err) {
    console.error("Update patient error:", err);
    return res.status(500).json({ error: "Failed to update patient" });
  }
});

export default router;
