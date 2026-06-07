import mongoose from "mongoose";

const staffSchema = new mongoose.Schema({
  hospital_name: { type: String, required: true },
  post: {
    type: String,
    enum: ["Admin", "Doctor", "Nurse", "Pharmacist", "Receptionist"],
    required: true,
  },
  id_number: { type: String, required: true },
  username: { type: String, sparse: true, unique: true },
  email: { type: String, default: "" },
  full_name: { type: String, default: "" },
  department: { type: String, default: "" },
  phone: { type: String, default: "" },
  password_hash: { type: String, required: true },
  ward: { type: String, default: "" },
  rsa_public_key: { type: String, default: "" },
  rsa_private_key_encrypted: { type: String, default: "" },
  password_changed_at: { type: Date, default: Date.now },
  password_must_change: { type: Boolean, default: false },
  is_active: { type: Boolean, default: true },
  is_verified: { type: Boolean, default: false },
  last_login: { type: Date, default: null },
  failed_login_attempts: { type: Number, default: 0 },
  locked_until: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
});

staffSchema.index({ hospital_name: 1, id_number: 1 }, { unique: true });

export const Staff = mongoose.model("Staff", staffSchema);
