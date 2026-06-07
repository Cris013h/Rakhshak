import mongoose from "mongoose";

const appointmentSchema = new mongoose.Schema({
  patient_name: { type: String, required: true },
  doctor_name: { type: String, required: true },
  doctor_id: { type: String, default: "" },
  datetime: { type: Date, required: true },
  type: { type: String, default: "Checkup" },
  status: { type: String, enum: ["Scheduled", "Completed", "Cancelled"], default: "Scheduled" },
  created_at: { type: Date, default: Date.now },
});

export const Appointment = mongoose.model("Appointment", appointmentSchema);
