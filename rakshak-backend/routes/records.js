import express from "express";
import { MedicalRecord, encryptRecordContent, encryptMedications } from "../models/MedicalRecord.js";
import { Patient } from "../models/Patient.js";
import { Prescription } from "../models/Prescription.js";
import { Staff } from "../models/Staff.js";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { generateTxHash, logDataAccessOnChain, logRecordSignatureOnChain } from "../services/blockchain.js";
import { signRecord, verifySignature } from "../services/signatureService.js";

const router = express.Router();

router.use(authenticateToken);

async function logRecordAction(req, action, details = {}) {
  const ipAddress = getClientIp(req);
  const onChainHash = await logDataAccessOnChain({
    idNumber: req.user.idNumber,
    hospitalName: req.user.hospitalName,
    post: req.user.post,
    dataType: details.dataType || action,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action,
    details: { hospital_name: req.user.hospitalName, post: req.user.post, ...details },
    ip_address: ipAddress,
    tx_hash: onChainHash || generateTxHash({ staffId: req.user.idNumber, action, ipAddress }),
  });

  return onChainHash;
}

router.post("/create", requireRole("Doctor"), async (req, res) => {
  try {
    const { patientId, recordType, content, medications, followUpDate } = req.body;

    if (!patientId || !recordType || !content) {
      return res.status(400).json({ error: "patientId, recordType, and content are required" });
    }

    const patient = await Patient.findOne({
      $or: [{ patientId: patientId.toUpperCase() }, { _id: patientId }],
    });

    if (!patient) return res.status(404).json({ error: "Patient not found" });

    const doctor = await Staff.findOne({ id_number: req.user.idNumber });
    if (!doctor) return res.status(404).json({ error: "Doctor not found" });

    const encryptedContent = encryptRecordContent(content);
    const encryptedMeds = encryptMedications(medications || []);

    const signature = signRecord(req.user.idNumber, encryptedContent, doctor.rsa_private_key_encrypted);

    const recordHash = generateTxHash({ content: encryptedContent, doctorId: req.user.idNumber });
    const blockchainTxHash = await logRecordSignatureOnChain({
      idNumber: req.user.idNumber,
      recordHash,
      valid: true,
    });

    const record = await MedicalRecord.create({
      patientId: patient.patientId || patient._id.toString(),
      doctorId: req.user.idNumber,
      hospitalName: req.user.hospitalName,
      recordType,
      encryptedContent,
      medications: encryptedMeds,
      signature,
      signedAt: new Date(),
      blockchainTxHash: blockchainTxHash || "",
      verificationStatus: "verified",
      followUpDate: followUpDate ? new Date(followUpDate) : null,
    });

    await logRecordAction(req, "RECORD_CREATED", {
      dataType: `RECORD_CREATED:${patient.patientId}`,
      recordId: record._id.toString(),
    });

    if (recordType === "prescription" && medications?.length) {
      const patientName = Patient.decryptDocument(patient).fullName || Patient.decryptDocument(patient).name;
      for (const med of medications) {
        if (med.name) {
          await Prescription.create({
            patient_name: patientName,
            patient_id: patient._id,
            medication: med.name,
            dosage: `${med.dosage || ""} ${med.frequency || ""} ${med.duration || ""}`.trim(),
            doctor_id: req.user.idNumber,
            status: "PENDING",
          });
        }
      }
    }

    return res.status(201).json({
      success: true,
      recordId: record._id,
      signature,
      record: record.toDecrypted(),
      blockchainTxHash,
    });
  } catch (err) {
    console.error("Create record error:", err);
    return res.status(500).json({ error: "Failed to create record" });
  }
});

router.get("/patient/:patientId", requireRole("Doctor", "Admin", "Nurse"), async (req, res) => {
  try {
    const records = await MedicalRecord.find({
      patientId: req.params.patientId.toUpperCase(),
    }).sort({ createdAt: -1 });

    const doctor = await Staff.findOne({ id_number: req.user.idNumber });
    const results = [];

    for (const record of records) {
      const docStaff = await Staff.findOne({ id_number: record.doctorId });
      const verification = await verifySignature(
        record.doctorId,
        record.encryptedContent,
        record.signature,
        docStaff?.rsa_public_key
      );

      record.verificationStatus = verification.verified ? "verified" : "tampered";
      await record.save();

      results.push({
        ...record.toDecrypted(),
        verificationStatus: record.verificationStatus,
        doctorId: record.doctorId,
        signedAt: record.signedAt,
        blockchainTxHash: record.blockchainTxHash,
      });
    }

    await logRecordAction(req, "RECORD_ACCESS", { dataType: `Records for ${req.params.patientId}` });
    return res.json({ records: results });
  } catch (err) {
    console.error("Get patient records error:", err);
    return res.status(500).json({ error: "Failed to fetch records" });
  }
});

router.put("/update/:recordId", requireRole("Doctor"), async (req, res) => {
  try {
    const record = await MedicalRecord.findById(req.params.recordId);
    if (!record) return res.status(404).json({ error: "Record not found" });
    if (record.doctorId !== req.user.idNumber) return res.status(403).json({ error: "Only creator can update" });

    record.recordHistory.push({
      encryptedContent: record.encryptedContent,
      signature: record.signature,
      signedAt: record.signedAt,
      updatedAt: new Date(),
    });

    const doctor = await Staff.findOne({ id_number: req.user.idNumber });
    const { content, medications, recordType, followUpDate } = req.body;

    if (content) record.encryptedContent = encryptRecordContent(content);
    if (medications) record.medications = encryptMedications(medications);
    if (recordType) record.recordType = recordType;
    if (followUpDate) record.followUpDate = new Date(followUpDate);

    record.signature = signRecord(req.user.idNumber, record.encryptedContent, doctor.rsa_private_key_encrypted);
    record.signedAt = new Date();
    record.updatedAt = new Date();
    record.verificationStatus = "verified";

    await record.save();
    await logRecordAction(req, "RECORD_UPDATED", { recordId: record._id.toString() });

    return res.json({ success: true, record: record.toDecrypted() });
  } catch (err) {
    console.error("Update record error:", err);
    return res.status(500).json({ error: "Failed to update record" });
  }
});

router.get("/verify/:recordId", requireRole("Doctor", "Admin", "Nurse", "Receptionist"), async (req, res) => {
  try {
    const record = await MedicalRecord.findById(req.params.recordId);
    if (!record) return res.status(404).json({ error: "Record not found" });

    const doctor = await Staff.findOne({ id_number: record.doctorId });
    const verification = await verifySignature(
      record.doctorId,
      record.encryptedContent,
      record.signature,
      doctor?.rsa_public_key
    );

    record.verificationStatus = verification.verified ? "verified" : "tampered";
    await record.save();

    return res.json({
      verified: verification.verified,
      recordId: record._id,
      createdBy: record.doctorId,
      signedAt: record.signedAt,
      signature: record.signature,
      publicKey: doctor?.rsa_public_key || "",
      blockchainTxHash: record.blockchainTxHash,
      status: verification.verified ? "VERIFIED — Record Untampered" : "TAMPERED — Signature Mismatch",
      reason: verification.reason,
    });
  } catch (err) {
    console.error("Verify record error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});

router.get("/all", requireRole("Admin"), async (req, res) => {
  try {
    const records = await MedicalRecord.find().sort({ createdAt: -1 }).limit(200);
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
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch records" });
  }
});

export default router;
