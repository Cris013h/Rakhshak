import mongoose from "mongoose";

const staffSchema = new mongoose.Schema({
  hospital_name: { type: String, required: true },
  post: {
    type: String,
    enum: ["Admin", "Doctor", "Nurse", "Pharmacist", "Receptionist"],
    required: true,
  },
  id_number: { type: String, required: true },
  password_hash: { type: String, required: true },
  ward: { type: String, default: "" },
  failed_login_attempts: { type: Number, default: 0 },
  locked_until: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
});

staffSchema.index({ hospital_name: 1, id_number: 1 }, { unique: true });

export const Staff = mongoose.model("Staff", staffSchema);
