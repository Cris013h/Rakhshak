import mongoose from "mongoose";

const lockedAccountSchema = new mongoose.Schema({
  idNumber: { type: String, required: true, unique: true, index: true },
  hospitalName: { type: String, default: "" },
  lockedUntil: { type: Date, required: true },
  failedAttempts: { type: Number, default: 3 },
  createdAt: { type: Date, default: Date.now },
});

export const LockedAccount = mongoose.model("LockedAccount", lockedAccountSchema);
