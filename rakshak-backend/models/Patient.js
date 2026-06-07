import mongoose from "mongoose";

const patientSchema = new mongoose.Schema({
  name: { type: String, required: true },
  age: { type: Number, required: true },
  ward: { type: String, required: true },
  assigned_doctor_id: { type: String, required: true },
  condition: { type: String, default: "" },
  status: { type: String, default: "Stable" },
  medical_notes: { type: String, default: "" },
  created_at: { type: Date, default: Date.now },
});

export const Patient = mongoose.model("Patient", patientSchema);
