import mongoose from "mongoose";

const ATTACK_TYPES = [
  "FLOOD_ATTACK",
  "BRUTE_FORCE_ATTACK",
  "SQL_INJECTION_ATTEMPT",
  "XSS_ATTEMPT",
  "RATE_LIMIT_EXCEEDED",
];

const firewallLogSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  attackType: { type: String, enum: ATTACK_TYPES, required: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  requestDetails: { type: mongoose.Schema.Types.Mixed, default: {} },
  attempts: { type: Number, default: 1 },
  status: { type: String, enum: ["Blocked", "Unblocked"], default: "Blocked" },
  tx_hash: { type: String, default: "" },
});

firewallLogSchema.index({ ip: 1, status: 1 });

export const FirewallLog = mongoose.model("FirewallLog", firewallLogSchema);
export { ATTACK_TYPES };
