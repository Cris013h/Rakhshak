import mongoose from "mongoose";
import dotenv from "dotenv";
import crypto from "crypto";
import { Staff } from "./models/Staff.js";
import { Patient } from "./models/Patient.js";
import { Prescription } from "./models/Prescription.js";
import { Appointment } from "./models/Appointment.js";
import { AuditLog } from "./models/AuditLog.js";

dotenv.config();

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function generateTxHash(data) {
  const payload = JSON.stringify({ ...data, nonce: crypto.randomBytes(16).toString("hex"), ts: Date.now() });
  return "0x" + crypto.createHash("sha256").update(payload).digest("hex");
}

const STAFF_SEED = [
  { hospital_name: "City General", post: "Admin", id_number: "ADM001", password: "admin123", ward: "" },
  { hospital_name: "City General", post: "Doctor", id_number: "DOC001", password: "doc123", ward: "" },
  { hospital_name: "City General", post: "Nurse", id_number: "NRS001", password: "nurse123", ward: "Ward A" },
  { hospital_name: "City General", post: "Pharmacist", id_number: "PHA001", password: "pharma123", ward: "" },
  { hospital_name: "City General", post: "Receptionist", id_number: "REC001", password: "recep123", ward: "" },
];

const PATIENTS_SEED = [
  { name: "Rajesh Kumar", age: 54, ward: "Ward A", assigned_doctor_id: "DOC001", condition: "Hypertension", status: "Stable", medical_notes: "BP monitoring required. Currently on Amlodipine 5mg." },
  { name: "Priya Sharma", age: 32, ward: "Ward B", assigned_doctor_id: "DOC001", condition: "Prenatal Care", status: "Monitoring", medical_notes: "32 weeks gestation. Regular ultrasounds scheduled." },
  { name: "Amit Patel", age: 67, ward: "Ward A", assigned_doctor_id: "DOC001", condition: "Post-surgery Recovery", status: "Critical", medical_notes: "Hip replacement surgery 3 days ago. Watch for infection." },
  { name: "Sunita Devi", age: 45, ward: "Ward A", assigned_doctor_id: "DOC001", condition: "Diabetes Type 2", status: "Stable", medical_notes: "HbA1c at 7.2%. Metformin 500mg twice daily." },
  { name: "Vikram Singh", age: 28, ward: "Ward C", assigned_doctor_id: "DOC001", condition: "Fracture", status: "Stable", medical_notes: "Right femur fracture. Cast applied, follow-up in 6 weeks." },
  { name: "Anita Rao", age: 61, ward: "Ward A", assigned_doctor_id: "DOC001", condition: "Arrhythmia", status: "Monitoring", medical_notes: "Atrial fibrillation. On Warfarin 2mg daily." },
  { name: "Deepak Verma", age: 50, ward: "Ward B", assigned_doctor_id: "DOC001", condition: "Pneumonia", status: "Monitoring", medical_notes: "Chest X-ray shows left lower lobe infiltrate." },
  { name: "Kavita Joshi", age: 38, ward: "Ward A", assigned_doctor_id: "DOC001", condition: "Asthma", status: "Stable", medical_notes: "Mild persistent asthma. Using Salbutamol inhaler PRN." },
  { name: "Ravi Gupta", age: 72, ward: "Ward C", assigned_doctor_id: "DOC001", condition: "COPD", status: "Critical", medical_notes: "On supplemental O2 2L/min. Spirometry shows severe obstruction." },
  { name: "Meera Nair", age: 29, ward: "Ward B", assigned_doctor_id: "DOC001", condition: "Appendicitis", status: "Stable", medical_notes: "Post-appendectomy day 2. Tolerating oral fluids." },
];

const PRESCRIPTIONS_SEED = [
  { patient_name: "Rajesh Kumar", medication: "Amlodipine 5mg", dosage: "1x daily", doctor_id: "DOC001", status: "PENDING" },
  { patient_name: "Sunita Devi", medication: "Metformin 500mg", dosage: "2x daily", doctor_id: "DOC001", status: "PENDING" },
  { patient_name: "Amit Patel", medication: "Morphine 10mg", dosage: "As needed", doctor_id: "DOC001", status: "PENDING" },
  { patient_name: "Anita Rao", medication: "Warfarin 2mg", dosage: "1x daily", doctor_id: "DOC001", status: "FILLED" },
  { patient_name: "Deepak Verma", medication: "Amoxicillin 500mg", dosage: "3x daily", doctor_id: "DOC001", status: "PENDING" },
  { patient_name: "Kavita Joshi", medication: "Salbutamol Inhaler", dosage: "PRN", doctor_id: "DOC001", status: "FILLED" },
  { patient_name: "Ravi Gupta", medication: "Tiotropium 18mcg", dosage: "1x daily", doctor_id: "DOC001", status: "PENDING" },
  { patient_name: "Meera Nair", medication: "Paracetamol 500mg", dosage: "As needed", doctor_id: "DOC001", status: "PENDING" },
];

const APPOINTMENTS_SEED = [
  { patient_name: "Rajesh Kumar", doctor_name: "Dr. Mehta", doctor_id: "DOC001", datetime: new Date("2026-06-08T09:00"), type: "Follow-up" },
  { patient_name: "Priya Sharma", doctor_name: "Dr. Nair", doctor_id: "DOC001", datetime: new Date("2026-06-08T10:30"), type: "Checkup" },
  { patient_name: "Vikram Singh", doctor_name: "Dr. Gupta", doctor_id: "DOC001", datetime: new Date("2026-06-08T14:00"), type: "Orthopedic" },
  { patient_name: "Anita Rao", doctor_name: "Dr. Mehta", doctor_id: "DOC001", datetime: new Date("2026-06-09T11:00"), type: "Cardiology" },
  { patient_name: "Deepak Verma", doctor_name: "Dr. Patel", doctor_id: "DOC001", datetime: new Date("2026-06-09T09:30"), type: "Follow-up" },
  { patient_name: "Kavita Joshi", doctor_name: "Dr. Mehta", doctor_id: "DOC001", datetime: new Date("2026-06-10T10:00"), type: "Respiratory" },
  { patient_name: "Ravi Gupta", doctor_name: "Dr. Patel", doctor_id: "DOC001", datetime: new Date("2026-06-10T14:30"), type: "Pulmonology" },
  { patient_name: "Meera Nair", doctor_name: "Dr. Gupta", doctor_id: "DOC001", datetime: new Date("2026-06-11T11:00"), type: "Post-op" },
];

async function main() {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/rakshak";
  await mongoose.connect(uri);
  console.log("Connected to MongoDB");

  await Staff.deleteMany({});
  await Patient.deleteMany({});
  await Prescription.deleteMany({});
  await Appointment.deleteMany({});
  await AuditLog.deleteMany({});

  console.log("\nRegistering staff...");
  for (const s of STAFF_SEED) {
    await Staff.create({
      hospital_name: s.hospital_name,
      post: s.post,
      id_number: s.id_number,
      password_hash: hashPassword(s.password),
      ward: s.ward,
    });
    console.log(`  Registered ${s.id_number} (${s.post})`);
  }

  console.log("\nSeeding patients...");
  for (const p of PATIENTS_SEED) {
    await Patient.create(p);
    console.log(`  Added patient: ${p.name}`);
  }

  console.log("\nSeeding prescriptions...");
  for (const rx of PRESCRIPTIONS_SEED) {
    await Prescription.create(rx);
    console.log(`  Added prescription: ${rx.medication} for ${rx.patient_name}`);
  }

  console.log("\nSeeding appointments...");
  for (const a of APPOINTMENTS_SEED) {
    await Appointment.create(a);
    console.log(`  Added appointment: ${a.patient_name} with ${a.doctor_name}`);
  }

  console.log("\nSeeding audit log entries...");
  const seedAudits = [
    { staff_id: "ADM001", action: "LOGIN", details: { hospital_name: "City General", post: "Admin", success: true } },
    { staff_id: "DOC001", action: "LOGIN", details: { hospital_name: "City General", post: "Doctor", success: true } },
    { staff_id: "DOC001", action: "RECORD_ACCESS", details: { data_accessed: "Patient Record: Rajesh Kumar", post: "Doctor" } },
    { staff_id: "DOC001", action: "RECORD_ACCESS", details: { data_accessed: "Patient Record: Amit Patel", post: "Doctor" } },
    { staff_id: "NRS001", action: "LOGIN", details: { hospital_name: "City General", post: "Nurse", success: true } },
    { staff_id: "PHA001", action: "LOGIN", details: { hospital_name: "City General", post: "Pharmacist", success: true } },
    { staff_id: "REC001", action: "LOGIN", details: { hospital_name: "City General", post: "Receptionist", success: true } },
    { staff_id: "UNKNOWN", action: "LOGIN", details: { hospital_name: "City General", post: "Admin", success: false } },
  ];

  for (const entry of seedAudits) {
    const txHash = generateTxHash(entry);
    await AuditLog.create({
      ...entry,
      ip_address: "127.0.0.1",
      tx_hash: txHash,
      created_at: new Date(Date.now() - Math.random() * 3600000),
    });
  }
  console.log(`  Added ${seedAudits.length} audit entries`);

  console.log("\n=== Demo Credentials ===");
  for (const s of STAFF_SEED) {
    console.log(`  Hospital: "${s.hospital_name}" | Post: ${s.post} | ID: ${s.id_number} | Password: ${s.password}`);
  }

  console.log("\nSeed complete.");
  await mongoose.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
