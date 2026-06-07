import mongoose from "mongoose";

const preRegisteredStaffSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  idNumber: { type: String, required: true, unique: true },
  post: {
    type: String,
    enum: ["Doctor", "Nurse", "Receptionist", "Pharmacist", "Admin"],
    required: true,
  },
  hospitalName: { type: String, required: true },
  department: { type: String, default: "" },
  email: { type: String, required: true },
  phone: { type: String, default: "" },
  startDate: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ["pending", "active", "locked", "suspended"],
    default: "pending",
  },
  registeredBy: { type: String, required: true },
  registeredAt: { type: Date, default: Date.now },
  activatedAt: { type: Date, default: null },
  blockchainTxHash: { type: String, default: "" },
});

export const PreRegisteredStaff = mongoose.model("PreRegisteredStaff", preRegisteredStaffSchema);
