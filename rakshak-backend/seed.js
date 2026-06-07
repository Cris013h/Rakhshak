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

function patientSeed(entry) {
  return {
    name: entry.name,
    dateOfBirth: entry.dob,
    age: entry.age,
    ward: entry.ward,
    assigned_doctor_id: "DOC001",
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
  patientSeed({ name: "Rajesh Kumar", dob: "1972-03-15", age: 54, ward: "Ward A", condition: "Hypertension", status: "Stable", medical_notes: "BP monitoring required. Currently on Amlodipine 5mg.", rx: "Amlodipine 5mg daily", insurance: "INS-RAJ-5401", address: "12 MG Road, Mumbai", phone: "+91-9876543210", emergency: "Sunita Kumar +91-9876543211" }),
  patientSeed({ name: "Priya Sharma", dob: "1994-08-22", age: 32, ward: "Ward B", condition: "Prenatal Care", status: "Monitoring", medical_notes: "32 weeks gestation. Regular ultrasounds scheduled.", rx: "Prenatal vitamins", insurance: "INS-PRI-3202", address: "45 Park Street, Delhi", phone: "+91-9876543220", emergency: "Rahul Sharma +91-9876543221" }),
  patientSeed({ name: "Amit Patel", dob: "1959-11-03", age: 67, ward: "Ward A", condition: "Post-surgery Recovery", status: "Critical", medical_notes: "Hip replacement surgery 3 days ago. Watch for infection.", rx: "Morphine 10mg PRN", insurance: "INS-AMI-6703", address: "78 Ring Road, Ahmedabad", phone: "+91-9876543230", emergency: "Neha Patel +91-9876543231" }),
  patientSeed({ name: "Sunita Devi", dob: "1981-01-28", age: 45, ward: "Ward A", condition: "Diabetes Type 2", status: "Stable", medical_notes: "HbA1c at 7.2%. Metformin 500mg twice daily.", rx: "Metformin 500mg BID", insurance: "INS-SUN-4504", address: "23 Civil Lines, Jaipur", phone: "+91-9876543240", emergency: "Raj Devi +91-9876543241" }),
  patientSeed({ name: "Vikram Singh", dob: "1998-06-10", age: 28, ward: "Ward C", condition: "Fracture", status: "Stable", medical_notes: "Right femur fracture. Cast applied, follow-up in 6 weeks.", rx: "Ibuprofen 400mg TID", insurance: "INS-VIK-2805", address: "56 Mall Road, Chandigarh", phone: "+91-9876543250", emergency: "Harpreet Singh +91-9876543251" }),
  patientSeed({ name: "Anita Rao", dob: "1965-09-17", age: 61, ward: "Ward A", condition: "Arrhythmia", status: "Monitoring", medical_notes: "Atrial fibrillation. On Warfarin 2mg daily.", rx: "Warfarin 2mg daily", insurance: "INS-ANI-6106", address: "89 Residency Road, Bangalore", phone: "+91-9876543260", emergency: "Suresh Rao +91-9876543261" }),
  patientSeed({ name: "Deepak Verma", dob: "1976-04-05", age: 50, ward: "Ward B", condition: "Pneumonia", status: "Monitoring", medical_notes: "Chest X-ray shows left lower lobe infiltrate.", rx: "Amoxicillin 500mg TID", insurance: "INS-DEE-5007", address: "34 Station Road, Lucknow", phone: "+91-9876543270", emergency: "Pooja Verma +91-9876543271" }),
  patientSeed({ name: "Kavita Joshi", dob: "1988-12-30", age: 38, ward: "Ward A", condition: "Asthma", status: "Stable", medical_notes: "Mild persistent asthma. Using Salbutamol inhaler PRN.", rx: "Salbutamol inhaler PRN", insurance: "INS-KAV-3808", address: "67 Lake View, Pune", phone: "+91-9876543280", emergency: "Ajay Joshi +91-9876543281" }),
  patientSeed({ name: "Ravi Gupta", dob: "1954-02-14", age: 72, ward: "Ward C", condition: "COPD", status: "Critical", medical_notes: "On supplemental O2 2L/min. Spirometry shows severe obstruction.", rx: "Tiotropium 18mcg daily", insurance: "INS-RAV-7209", address: "91 GT Road, Kolkata", phone: "+91-9876543290", emergency: "Lata Gupta +91-9876543291" }),
  patientSeed({ name: "Meera Nair", dob: "1997-07-19", age: 29, ward: "Ward B", condition: "Appendicitis", status: "Stable", medical_notes: "Post-appendectomy day 2. Tolerating oral fluids.", rx: "Paracetamol 500mg PRN", insurance: "INS-MEE-2910", address: "15 Marine Drive, Kochi", phone: "+91-9876543300", emergency: "Arun Nair +91-9876543301" }),
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

  console.log("\nSeeding patients (AES-256 encrypted at rest)...");
  for (const p of PATIENTS_SEED) {
    const patient = await Patient.create(p);
    const decrypted = patient.toDecrypted();
    console.log(`  Added patient: ${decrypted.name}`);
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
