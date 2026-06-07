import mongoose from "mongoose";
import dotenv from "dotenv";
import crypto from "crypto";
import { Staff } from "./models/Staff.js";
import { PreRegisteredStaff } from "./models/PreRegisteredStaff.js";
import { Patient } from "./models/Patient.js";
import { Prescription } from "./models/Prescription.js";
import { Appointment } from "./models/Appointment.js";
import { AuditLog } from "./models/AuditLog.js";
import { OTPLog } from "./models/OTPLog.js";
import { PasswordHistory } from "./models/PasswordHistory.js";
import { hashPasswordBcrypt } from "./services/passwordPolicy.js";
import { setupStaffSignatureKeys } from "./services/signatureService.js";
import {
  preRegisterStaffOnChain,
  activateStaffOnChain,
  registerStaffOnChain,
  isBlockchainEnabled,
} from "./services/blockchain.js";

dotenv.config();

function generateTxHash(data) {
  const payload = JSON.stringify({ ...data, nonce: crypto.randomBytes(16).toString("hex"), ts: Date.now() });
  return "0x" + crypto.createHash("sha256").update(payload).digest("hex");
}

const HOSPITAL = "City General";

const STAFF_SEED = [
  { fullName: "System Admin", post: "Admin", id_number: "ADM001", username: "admin", password: "Admin@123456", email: "admin@citygeneral.com", department: "IT Security", ward: "" },
  { fullName: "Dr. Mehta", post: "Doctor", id_number: "DOC001", username: "drmehta", password: "Doc@123456", email: "doc001@citygeneral.com", department: "General Medicine", ward: "" },
  { fullName: "Nurse Priya", post: "Nurse", id_number: "NRS001", username: "nursepriya", password: "Nurse@123456", email: "nrs001@citygeneral.com", department: "Ward A", ward: "Ward A" },
  { fullName: "Pharmacist Kumar", post: "Pharmacist", id_number: "PHA001", username: "pharmakumar", password: "Pharma@123456", email: "pha001@citygeneral.com", department: "Pharmacy", ward: "" },
  { fullName: "Receptionist Singh", post: "Receptionist", id_number: "REC001", username: "recsingh", password: "Recep@123456", email: "rec001@citygeneral.com", department: "Front Desk", ward: "" },
];

function patientSeed(entry) {
  return {
    patientId: entry.patientId,
    fullName: entry.name,
    name: entry.name,
    dateOfBirth: entry.dob,
    age: entry.age,
    ward: entry.ward,
    assigned_doctor_id: "DOC001",
    assignedDoctors: ["DOC001"],
    hospitalName: HOSPITAL,
    registeredBy: "REC001",
    diagnosis: entry.condition,
    prescription: entry.rx,
    medicalHistory: entry.medical_notes,
    insuranceNumber: entry.insurance,
    address: entry.address,
    phoneNumber: entry.phone,
    emergencyContact: entry.emergency,
    condition: entry.condition,
    status: entry.status,
    medical_notes: entry.medical_notes,
  };
}

const PATIENTS_SEED = [
  patientSeed({ patientId: "PAT-0001", name: "Rajesh Kumar", dob: "1972-03-15", age: 54, ward: "Ward A", condition: "Hypertension", status: "Stable", medical_notes: "BP monitoring required.", rx: "Amlodipine 5mg daily", insurance: "INS-RAJ-5401", address: "12 MG Road, Mumbai", phone: "+91-9876543210", emergency: "Sunita Kumar +91-9876543211" }),
  patientSeed({ patientId: "PAT-0002", name: "Priya Sharma", dob: "1994-08-22", age: 32, ward: "Ward B", condition: "Prenatal Care", status: "Monitoring", medical_notes: "32 weeks gestation.", rx: "Prenatal vitamins", insurance: "INS-PRI-3202", address: "45 Park Street, Delhi", phone: "+91-9876543220", emergency: "Rahul Sharma +91-9876543221" }),
  patientSeed({ patientId: "PAT-0003", name: "Amit Patel", dob: "1959-11-03", age: 67, ward: "Ward A", condition: "Post-surgery Recovery", status: "Critical", medical_notes: "Hip replacement surgery.", rx: "Morphine 10mg PRN", insurance: "INS-AMI-6703", address: "78 Ring Road, Ahmedabad", phone: "+91-9876543230", emergency: "Neha Patel +91-9876543231" }),
  patientSeed({ patientId: "PAT-0004", name: "Sunita Devi", dob: "1981-01-28", age: 45, ward: "Ward A", condition: "Diabetes Type 2", status: "Stable", medical_notes: "HbA1c at 7.2%.", rx: "Metformin 500mg BID", insurance: "INS-SUN-4504", address: "23 Civil Lines, Jaipur", phone: "+91-9876543240", emergency: "Raj Devi +91-9876543241" }),
  patientSeed({ patientId: "PAT-0005", name: "Vikram Singh", dob: "1998-06-10", age: 28, ward: "Ward C", condition: "Fracture", status: "Stable", medical_notes: "Right femur fracture.", rx: "Ibuprofen 400mg TID", insurance: "INS-VIK-2805", address: "56 Mall Road, Chandigarh", phone: "+91-9876543250", emergency: "Harpreet Singh +91-9876543251" }),
];

async function seedStaffMember(s) {
  console.log(`  Pre-registering ${s.id_number}...`);

  await PreRegisteredStaff.create({
    fullName: s.fullName,
    idNumber: s.id_number,
    post: s.post,
    hospitalName: HOSPITAL,
    department: s.department,
    email: s.email,
    status: "active",
    registeredBy: "ADM001",
    activatedAt: new Date(),
  });

  if (isBlockchainEnabled()) {
    await preRegisterStaffOnChain({
      fullName: s.fullName,
      idNumber: s.id_number,
      post: s.post,
      hospitalName: HOSPITAL,
      department: s.department,
      email: s.email,
    });
    console.log(`  Activating ${s.id_number}...`);
    await activateStaffOnChain(s.id_number, s.password);
  } else {
    await registerStaffOnChain({
      hospitalName: HOSPITAL,
      post: s.post,
      idNumber: s.id_number,
      password: s.password,
    });
  }

  const passwordHash = await hashPasswordBcrypt(s.password);
  const { publicKey, encryptedPrivateKey } = await setupStaffSignatureKeys(s.id_number);

  await Staff.create({
    hospital_name: HOSPITAL,
    post: s.post,
    id_number: s.id_number,
    username: s.username,
    email: s.email,
    full_name: s.fullName,
    department: s.department,
    password_hash: passwordHash,
    ward: s.ward,
    rsa_public_key: publicKey,
    rsa_private_key_encrypted: encryptedPrivateKey,
    password_changed_at: new Date(),
    is_active: true,
    is_verified: true,
  });
}

async function main() {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/rakshak";
  await mongoose.connect(uri);
  console.log("Connected to MongoDB");

  await Staff.deleteMany({});
  await PreRegisteredStaff.deleteMany({});
  await Patient.deleteMany({});
  await Prescription.deleteMany({});
  await Appointment.deleteMany({});
  await AuditLog.deleteMany({});
  await OTPLog.deleteMany({});
  await PasswordHistory.deleteMany({});

  console.log("\nPre-registering staff on blockchain...");
  for (const s of STAFF_SEED) {
    await seedStaffMember(s);
  }
  console.log("All staff registered and activated");

  console.log("\nSeeding patients (AES-256 encrypted at rest)...");
  for (const p of PATIENTS_SEED) {
    const patient = await Patient.create(p);
    console.log(`  Added patient: ${patient.toDecrypted().name} (${p.patientId})`);
  }

  const PRESCRIPTIONS_SEED = [
    { patient_name: "Rajesh Kumar", medication: "Amlodipine 5mg", dosage: "1x daily", doctor_id: "DOC001", status: "PENDING" },
    { patient_name: "Sunita Devi", medication: "Metformin 500mg", dosage: "2x daily", doctor_id: "DOC001", status: "PENDING" },
    { patient_name: "Amit Patel", medication: "Morphine 10mg", dosage: "As needed", doctor_id: "DOC001", status: "PENDING" },
  ];

  for (const rx of PRESCRIPTIONS_SEED) {
    await Prescription.create(rx);
  }

  const APPOINTMENTS_SEED = [
    { patient_name: "Rajesh Kumar", doctor_name: "Dr. Mehta", doctor_id: "DOC001", datetime: new Date("2026-06-08T09:00"), type: "Follow-up" },
    { patient_name: "Priya Sharma", doctor_name: "Dr. Mehta", doctor_id: "DOC001", datetime: new Date("2026-06-08T10:30"), type: "Checkup" },
  ];

  for (const a of APPOINTMENTS_SEED) {
    await Appointment.create(a);
  }

  const seedAudits = [
    { staff_id: "ADM001", action: "LOGIN", details: { hospital_name: HOSPITAL, post: "Admin", success: true } },
    { staff_id: "DOC001", action: "LOGIN", details: { hospital_name: HOSPITAL, post: "Doctor", success: true } },
    { staff_id: "REC001", action: "PATIENT_REGISTERED", details: { dataType: "PATIENT_REGISTERED:PAT-0001" } },
  ];

  for (const entry of seedAudits) {
    await AuditLog.create({ ...entry, ip_address: "127.0.0.1", tx_hash: generateTxHash(entry) });
  }

  console.log("\n═══ LOGIN CREDENTIALS ═══");
  console.log(`Hospital: ${HOSPITAL}`);
  console.log("Admin:        ADM001 / Admin@123456  (or username: admin)");
  console.log("Doctor:       DOC001 / Doc@123456    (or username: drmehta)");
  console.log("Nurse:        NRS001 / Nurse@123456  (or username: nursepriya)");
  console.log("Pharmacist:   PHA001 / Pharma@123456 (or username: pharmakumar)");
  console.log("Receptionist: REC001 / Recep@123456  (or username: recsingh)");
  console.log("Note: Passwords meet 12 char policy. Use login + OTP (check console for dev OTP).");

  console.log("\nSeed complete.");
  await mongoose.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
