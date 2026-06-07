import mongoose from "mongoose";
import { encryptAES, decryptAES, isEncrypted } from "../services/aesService.js";

export const SENSITIVE_FIELDS = [
  "name",
  "dateOfBirth",
  "diagnosis",
  "prescription",
  "medicalHistory",
  "insuranceNumber",
  "address",
  "phoneNumber",
  "emergencyContact",
];

const patientSchema = new mongoose.Schema({
  name: { type: String, required: true },
  dateOfBirth: { type: String, default: "" },
  age: { type: Number, required: true },
  ward: { type: String, required: true },
  assigned_doctor_id: { type: String, required: true },
  diagnosis: { type: String, default: "" },
  prescription: { type: String, default: "" },
  medicalHistory: { type: String, default: "" },
  insuranceNumber: { type: String, default: "" },
  address: { type: String, default: "" },
  phoneNumber: { type: String, default: "" },
  emergencyContact: { type: String, default: "" },
  condition: { type: String, default: "" },
  status: { type: String, default: "Stable" },
  medical_notes: { type: String, default: "" },
  created_at: { type: Date, default: Date.now },
});

patientSchema.pre("save", function encryptSensitiveFields(next) {
  try {
    for (const field of SENSITIVE_FIELDS) {
      const value = this[field];
      if (value && typeof value === "string" && !isEncrypted(value)) {
        this[field] = encryptAES(value);
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

  if (obj.condition) {
    obj.condition = decryptAES(obj.condition);
  }
  if (obj.medical_notes) {
    obj.medical_notes = decryptAES(obj.medical_notes);
  }

  if (!obj.diagnosis && obj.condition) {
    obj.diagnosis = obj.condition;
  }
  if (!obj.medicalHistory && obj.medical_notes) {
    obj.medicalHistory = obj.medical_notes;
  }

  return obj;
};

patientSchema.statics.decryptDocument = function decryptDocument(doc) {
  if (!doc) return null;
  if (typeof doc.toDecrypted === "function") {
    return doc.toDecrypted();
  }

  const patient = new Patient(doc);
  return patient.toDecrypted();
};

patientSchema.statics.decryptMany = function decryptMany(docs) {
  return docs.map((doc) => Patient.decryptDocument(doc));
};

export const Patient = mongoose.model("Patient", patientSchema);
