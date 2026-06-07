import mongoose from "mongoose";
import { encryptAES, decryptAES, isEncrypted } from "../services/aesService.js";

const medicationSchema = new mongoose.Schema({
  name: String,
  dosage: String,
  frequency: String,
  duration: String,
  instructions: String,
}, { _id: false });

const recordHistorySchema = new mongoose.Schema({
  encryptedContent: String,
  signature: String,
  signedAt: Date,
  updatedAt: { type: Date, default: Date.now },
}, { _id: false });

const medicalRecordSchema = new mongoose.Schema({
  patientId: { type: String, required: true, index: true },
  doctorId: { type: String, required: true, index: true },
  hospitalName: { type: String, required: true },
  recordType: {
    type: String,
    enum: ["diagnosis", "prescription", "lab_result", "clinical_note", "referral"],
    required: true,
  },
  encryptedContent: { type: String, required: true },
  medications: { type: String, default: "" },
  signature: { type: String, required: true },
  signedAt: { type: Date, default: Date.now },
  blockchainTxHash: { type: String, default: "" },
  verificationStatus: {
    type: String,
    enum: ["verified", "tampered", "unverified"],
    default: "unverified",
  },
  recordHistory: [recordHistorySchema],
  followUpDate: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

medicalRecordSchema.methods.getDecryptedContent = function getDecryptedContent() {
  return decryptAES(this.encryptedContent);
};

medicalRecordSchema.methods.getDecryptedMedications = function getDecryptedMedications() {
  if (!this.medications) return [];
  const decrypted = isEncrypted(this.medications) ? decryptAES(this.medications) : this.medications;
  try {
    return JSON.parse(decrypted);
  } catch {
    return [];
  }
};

medicalRecordSchema.methods.toDecrypted = function toDecrypted() {
  const obj = this.toObject();
  obj.content = this.getDecryptedContent();
  obj.medications = this.getDecryptedMedications();
  delete obj.encryptedContent;
  return obj;
};

export function encryptRecordContent(content) {
  return encryptAES(content);
}

export function encryptMedications(medications) {
  if (!medications || medications.length === 0) return "";
  return encryptAES(JSON.stringify(medications));
}

export const MedicalRecord = mongoose.model("MedicalRecord", medicalRecordSchema);
