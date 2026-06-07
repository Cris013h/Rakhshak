import mongoose from "mongoose";

const prescriptionSchema = new mongoose.Schema({
  patient_name: { type: String, required: true },
  patient_id: { type: mongoose.Schema.Types.ObjectId, ref: "Patient" },
  medication: { type: String, required: true },
  dosage: { type: String, required: true },
  doctor_id: { type: String, required: true },
  status: { type: String, enum: ["PENDING", "FILLED"], default: "PENDING" },
  created_at: { type: Date, default: Date.now },
});

export const Prescription = mongoose.model("Prescription", prescriptionSchema);
