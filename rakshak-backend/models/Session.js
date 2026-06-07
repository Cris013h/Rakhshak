import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
  staff_id: { type: String, required: true, index: true },
  token_jti: { type: String, required: true, unique: true },
  active: { type: Boolean, default: true },
  last_activity: { type: Date, default: Date.now },
  expires_at: { type: Date, required: true },
  ip_address: { type: String, default: "" },
});

export const Session = mongoose.model("Session", sessionSchema);
