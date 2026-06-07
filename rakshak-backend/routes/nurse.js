import express from "express";
import { Patient } from "../models/Patient.js";
import { authenticateToken, requireRole } from "../middleware/auth.js";

const router = express.Router();

router.use(authenticateToken, requireRole("Nurse"));

router.get("/ward-patients", async (req, res) => {
  const ward = req.user.ward || "Ward A";
  const patients = await Patient.find({ ward }).sort({ name: 1 }).lean();
  return res.json({ patients, ward });
});

export default router;
