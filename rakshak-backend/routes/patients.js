import express from "express";
import { Patient } from "../models/Patient.js";
import { Staff } from "../models/Staff.js";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { generateTxHash, logDataAccessOnChain } from "../services/blockchain.js";
import { checkAndFlagAnomaly } from "../services/anomalyDetection.js";

const router = express.Router();

router.use(authenticateToken);

async function generatePatientId() {
  const count = await Patient.countDocuments();
  return `PAT-${String(count + 1).padStart(4, "0")}`;
}

async function logPatientAccess(req, action, details = {}) {
  const ipAddress = getClientIp(req);
  const txHash = generateTxHash({ staffId: req.user.idNumber, action, ipAddress, ...details });

  let onChainHash = null;
  if (action.includes("PATIENT") || action === "RECORD_ACCESS") {
    onChainHash = await logDataAccessOnChain({
      idNumber: req.user.idNumber,
      hospitalName: req.user.hospitalName,
      post: req.user.post,
      dataType: details.dataType || action,
    });
  }

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action,
    details: { hospital_name: req.user.hospitalName, post: req.user.post, ...details },
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
  if (post === "Receptionist") return true;
  if (post === "Doctor") {
    const doctors = patient.assignedDoctors?.length ? patient.assignedDoctors : [patient.assigned_doctor_id];
    return doctors.includes(req.user.idNumber);
  }
  if (post === "Nurse") return patient.ward === (req.user.ward || "Ward A");
  return false;
}

router.get("/doctors", requireRole("Receptionist", "Admin"), async (req, res) => {
  const doctors = await Staff.find({
    hospital_name: req.user.hospitalName,
    post: "Doctor",
    is_active: true,
  }).select("id_number full_name department").lean();

  return res.json({
    doctors: doctors.map((d) => ({
      idNumber: d.id_number,
      fullName: d.full_name || d.id_number,
      department: d.department,
    })),
  });
});

router.post("/register", requireRole("Receptionist"), async (req, res) => {
  try {
    const {
      fullName, dateOfBirth, gender, address, phoneNumber,
      emergencyContactName, emergencyContactPhone, insuranceNumber,
      insuranceProvider, bloodGroup, allergies, specialNotes, assignedDoctor,
    } = req.body;

    if (!fullName || !dateOfBirth) {
      return res.status(400).json({ error: "Full name and date of birth are required" });
    }

    const patientId = await generatePatientId();
    const assignedDoctors = assignedDoctor ? [assignedDoctor] : [];

    const patient = await Patient.create({
      patientId,
      fullName,
      name: fullName,
      dateOfBirth,
      gender: gender || "",
      address: address || "",
      phoneNumber: phoneNumber || "",
      emergencyContactName: emergencyContactName || "",
      emergencyContactPhone: emergencyContactPhone || "",
      emergencyContact: emergencyContactPhone ? `${emergencyContactName} ${emergencyContactPhone}` : emergencyContactName || "",
      insuranceNumber: insuranceNumber || "",
      insuranceProvider: insuranceProvider || "",
      bloodGroup: bloodGroup || "",
      allergies: allergies || "",
      specialNotes: specialNotes || "",
      hospitalName: req.user.hospitalName,
      registeredBy: req.user.idNumber,
      registeredAt: new Date(),
      assigned_doctor_id: assignedDoctor || "",
      assignedDoctors,
      ward: "General",
    });

    const txHash = await logPatientAccess(req, "PATIENT_REGISTERED", {
      dataType: `PATIENT_REGISTERED:${patientId}`,
      patientId,
    });

    return res.status(201).json({
      success: true,
      patientId,
      patient: Patient.decryptDocument(patient),
      tx_hash: txHash,
    });
  } catch (err) {
    console.error("Register patient error:", err);
    return res.status(500).json({ error: "Failed to register patient" });
  }
});

router.get("/search", requireRole("Receptionist", "Doctor", "Admin"), async (req, res) => {
  try {
    const { name, id: patientId } = req.query;
    let filter = {};

    if (patientId) {
      filter = { patientId: patientId.toUpperCase() };
    } else if (name) {
      const all = await Patient.find({ hospitalName: req.user.hospitalName }).lean();
      const decrypted = Patient.decryptMany(all);
      const searchTerm = name.toLowerCase();
      const matched = decrypted.filter((p) =>
        (p.fullName || p.name || "").toLowerCase().includes(searchTerm)
      );
      await logPatientAccess(req, "PATIENT_SEARCH", { dataType: `Search: ${name}` });
      return res.json({ patients: matched });
    } else {
      return res.status(400).json({ error: "Provide name or patient ID" });
    }

    const patients = await Patient.find(filter).lean();
    const decrypted = Patient.decryptMany(patients).filter((p) => canAccessPatient(req, p));

    await logPatientAccess(req, "PATIENT_SEARCH", { dataType: `Search: ${patientId || name}` });
    return res.json({ patients: decrypted });
  } catch (err) {
    console.error("Search patients error:", err);
    return res.status(500).json({ error: "Search failed" });
  }
});

router.get("/all", requireRole("Receptionist", "Doctor", "Admin"), async (req, res) => {
  try {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    let filter = { hospitalName: req.user.hospitalName };

    if (req.user.post === "Doctor") {
      filter = {
        $or: [
          { assigned_doctor_id: req.user.idNumber },
          { assignedDoctors: req.user.idNumber },
        ],
      };
    }

    const [patients, total] = await Promise.all([
      Patient.find(filter).sort({ registeredAt: -1 }).skip(skip).limit(limit).lean(),
      Patient.countDocuments(filter),
    ]);

    const decrypted = Patient.decryptMany(patients);
    await logPatientAccess(req, "RECORD_ACCESS", { dataType: `Patient List page ${page}` });

    return res.json({ patients: decrypted, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error("List all patients error:", err);
    return res.status(500).json({ error: "Failed to fetch patients" });
  }
});

router.put("/update/:patientId", requireRole("Receptionist"), async (req, res) => {
  try {
    const patient = await Patient.findOne({ patientId: req.params.patientId.toUpperCase() });
    if (!patient) return res.status(404).json({ error: "Patient not found" });

    const updatable = [
      "fullName", "name", "dateOfBirth", "gender", "address", "phoneNumber",
      "emergencyContactName", "emergencyContactPhone", "insuranceNumber",
      "insuranceProvider", "bloodGroup", "allergies", "specialNotes",
    ];

    for (const field of updatable) {
      if (req.body[field] !== undefined) patient[field] = req.body[field];
    }

    if (req.body.fullName) patient.name = req.body.fullName;

    await patient.save();
    const txHash = await logPatientAccess(req, "PATIENT_UPDATE", { patientId: patient.patientId });

    return res.json({ success: true, patient: Patient.decryptDocument(patient), tx_hash: txHash });
  } catch (err) {
    console.error("Update patient error:", err);
    return res.status(500).json({ error: "Failed to update patient" });
  }
});

router.post("/create", requireRole("Doctor", "Admin", "Receptionist"), async (req, res) => {
  try {
    const patientId = await generatePatientId();
    const patient = await Patient.create({ ...req.body, patientId, name: req.body.name || req.body.fullName });
    const txHash = await logPatientAccess(req, "PATIENT_CREATE", { patientId });
    return res.status(201).json({ patient: Patient.decryptDocument(patient), tx_hash: txHash });
  } catch (err) {
    return res.status(500).json({ error: "Failed to create patient" });
  }
});

router.get("/", requireRole("Doctor", "Admin", "Nurse", "Receptionist"), async (req, res) => {
  try {
    let filter = {};
    if (req.user.post === "Doctor") filter = { assigned_doctor_id: req.user.idNumber };
    else if (req.user.post === "Nurse") filter = { ward: req.user.ward || "Ward A" };

    const patients = await Patient.find(filter).lean();
    const decrypted = Patient.decryptMany(patients);
    decrypted.sort((a, b) => (a.name || a.fullName || "").localeCompare(b.name || b.fullName || ""));
    await logPatientAccess(req, "RECORD_ACCESS", { dataType: "Patient List" });
    return res.json({ patients: decrypted });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch patients" });
  }
});

router.get("/:id", requireRole("Doctor", "Admin", "Nurse", "Receptionist"), async (req, res) => {
  try {
    let patient = await Patient.findById(req.params.id).catch(() => null);
    if (!patient) patient = await Patient.findOne({ patientId: req.params.id.toUpperCase() });
    if (!patient) return res.status(404).json({ error: "Patient not found" });
    if (!canAccessPatient(req, patient)) return res.status(403).json({ error: "Access denied" });

    const txHash = await logPatientAccess(req, "RECORD_ACCESS", {
      patientId: patient.patientId || patient._id.toString(),
      dataType: `Patient: ${patient.patientId}`,
    });

    return res.json({ patient: Patient.decryptDocument(patient), tx_hash: txHash });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch patient" });
  }
});

router.put("/:id", requireRole("Doctor", "Admin"), async (req, res) => {
  try {
    const patient = await Patient.findById(req.params.id);
    if (!patient) return res.status(404).json({ error: "Patient not found" });
    if (!canAccessPatient(req, patient)) return res.status(403).json({ error: "Access denied" });

    const updatable = [
      "name", "fullName", "dateOfBirth", "age", "ward", "assigned_doctor_id",
      "diagnosis", "prescription", "medicalHistory", "insuranceNumber",
      "address", "phoneNumber", "emergencyContact", "condition", "status", "medical_notes",
    ];

    for (const field of updatable) {
      if (req.body[field] !== undefined) patient[field] = req.body[field];
    }

    await patient.save();
    const txHash = await logPatientAccess(req, "PATIENT_UPDATE", { patientId: patient.patientId });
    return res.json({ patient: Patient.decryptDocument(patient), tx_hash: txHash });
  } catch (err) {
    return res.status(500).json({ error: "Failed to update patient" });
  }
});

export default router;
