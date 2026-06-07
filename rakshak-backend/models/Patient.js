import mongoose from "mongoose";
import { encryptAES, decryptAES, isEncrypted } from "../services/aesService.js";

export const SENSITIVE_FIELDS = [
  "name",
  "fullName",
  "dateOfBirth",
  "diagnosis",
  "prescription",
  "medicalHistory",
  "insuranceNumber",
  "address",
  "phoneNumber",
  "emergencyContact",
  "emergencyContactName",
  "emergencyContactPhone",
  "bloodGroup",
  "allergies",
  "specialNotes",
];

const patientSchema = new mongoose.Schema({
  patientId: { type: String, unique: true, sparse: true },
  name: { type: String, default: "" },
  fullName: { type: String, default: "" },
  dateOfBirth: { type: String, default: "" },
  gender: { type: String, default: "" },
  age: { type: Number, default: 0 },
  ward: { type: String, default: "General" },
  assigned_doctor_id: { type: String, default: "" },
  assignedDoctors: [{ type: String }],
  hospitalName: { type: String, default: "" },
  registeredBy: { type: String, default: "" },
  registeredAt: { type: Date, default: Date.now },
  diagnosis: { type: String, default: "" },
  prescription: { type: String, default: "" },
  medicalHistory: { type: String, default: "" },
  insuranceNumber: { type: String, default: "" },
  insuranceProvider: { type: String, default: "" },
  address: { type: String, default: "" },
  phoneNumber: { type: String, default: "" },
  emergencyContact: { type: String, default: "" },
  emergencyContactName: { type: String, default: "" },
  emergencyContactPhone: { type: String, default: "" },
  bloodGroup: { type: String, default: "" },
  allergies: { type: String, default: "" },
  specialNotes: { type: String, default: "" },
  condition: { type: String, default: "" },
  status: { type: String, default: "Stable" },
  medical_notes: { type: String, default: "" },
  created_at: { type: Date, default: Date.now },
});

function encryptField(value) {
  if (value && typeof value === "string" && value !== "" && !isEncrypted(value)) {
    return encryptAES(value);
  }
  return value;
}

patientSchema.pre("save", function encryptSensitiveFields(next) {
  try {
    if (this.fullName && !this.name) {
      this.name = this.fullName;
    }
    if (this.name && !this.fullName) {
      this.fullName = this.name;
    }

    for (const field of SENSITIVE_FIELDS) {
      if (this[field] !== undefined) {
        this[field] = encryptField(this[field]);
      }
    }

    if (this.condition && typeof this.condition === "string" && !isEncrypted(this.condition)) {
      this.diagnosis = this.diagnosis || this.condition;
      this.condition = encryptAES(this.condition);
    }

    if (this.medical_notes && typeof this.medical_notes === "string" && !isEncrypted(this.medical_notes)) {
      this.medicalHistory = this.medicalHistory || this.medical_notes;
      this.medical_notes = encryptAES(this.medical_notes);
    }

    next();
  } catch (err) {
    next(err);
  }
});

patientSchema.methods.toDecrypted = function toDecrypted() {
  const obj = this.toObject ? this.toObject() : { ...this };

  for (const field of SENSITIVE_FIELDS) {
    if (obj[field]) {
      obj[field] = decryptAES(obj[field]);
    }
  }

  if (obj.condition) obj.condition = decryptAES(obj.condition);
  if (obj.medical_notes) obj.medical_notes = decryptAES(obj.medical_notes);

  if (!obj.fullName && obj.name) obj.fullName = obj.name;
  if (!obj.name && obj.fullName) obj.name = obj.fullName;
  if (!obj.diagnosis && obj.condition) obj.diagnosis = obj.condition;
  if (!obj.medicalHistory && obj.medical_notes) obj.medicalHistory = obj.medical_notes;

  return obj;
};

patientSchema.statics.decryptDocument = function decryptDocument(doc) {
  if (!doc) return null;
  if (typeof doc.toDecrypted === "function") return doc.toDecrypted();
  const patient = new Patient(doc);
  return patient.toDecrypted();
};

patientSchema.statics.decryptMany = function decryptMany(docs) {
  return docs.map((doc) => Patient.decryptDocument(doc));
};

export const Patient = mongoose.model("Patient", patientSchema);
