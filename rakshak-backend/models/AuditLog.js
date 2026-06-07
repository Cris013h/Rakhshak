import mongoose from "mongoose";

const ACTION_TYPES = [
  "LOGIN",
  "LOGOUT",
  "RECORD_ACCESS",
  "SESSION_TIMEOUT",
  "LOCKOUT",
  "UNLOCK",
  "ANOMALY",
];

const auditLogSchema = new mongoose.Schema({
  staff_id: { type: String, required: true, index: true },
  action: { type: String, enum: ACTION_TYPES, required: true, index: true },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  ip_address: { type: String, default: "" },
  tx_hash: { type: String, default: "" },
  created_at: { type: Date, default: Date.now, index: true },
});

export const AuditLog = mongoose.model("AuditLog", auditLogSchema);
export { ACTION_TYPES };
