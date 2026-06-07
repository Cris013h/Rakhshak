import mongoose from "mongoose";

const passwordHistorySchema = new mongoose.Schema({
  idNumber: { type: String, required: true, index: true },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

export const PasswordHistory = mongoose.model("PasswordHistory", passwordHistorySchema);
