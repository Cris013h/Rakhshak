import mongoose from "mongoose";

const otpLogSchema = new mongoose.Schema({
  idNumber: { type: String, required: true, index: true },
  otpHash: { type: String, required: true },
  purpose: { type: String, enum: ["login", "signup"], default: "login" },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false },
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

otpLogSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 3600 });

export const OTPLog = mongoose.model("OTPLog", otpLogSchema);
