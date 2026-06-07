import express from "express";
import { Appointment } from "../models/Appointment.js";
import { AuditLog } from "../models/AuditLog.js";
import { authenticateToken, requireRole, getClientIp } from "../middleware/auth.js";
import { generateTxHash } from "../services/blockchain.js";

const router = express.Router();

router.use(authenticateToken, requireRole("Receptionist"));

router.get("/appointments", async (req, res) => {
  const appointments = await Appointment.find()
    .sort({ datetime: 1 })
    .lean();
  return res.json({ appointments });
});

router.post("/appointments", async (req, res) => {
  const { patient_name, doctor_name, datetime, type } = req.body;
  const ipAddress = getClientIp(req);

  if (!patient_name || !doctor_name || !datetime) {
    return res.status(400).json({ error: "patient_name, doctor_name, and datetime are required" });
  }

  const appointment = await Appointment.create({
    patient_name,
    doctor_name,
    datetime: new Date(datetime),
    type: type || "Checkup",
  });

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "RECORD_ACCESS",
    appointmentId: appointment._id.toString(),
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "RECORD_ACCESS",
    details: {
      data_accessed: `Created appointment for ${patient_name}`,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ appointment, tx_hash: txHash });
});

router.put("/appointments/:id", async (req, res) => {
  const ipAddress = getClientIp(req);
  const update = {};
  if (req.body.patient_name) update.patient_name = req.body.patient_name;
  if (req.body.doctor_name) update.doctor_name = req.body.doctor_name;
  if (req.body.datetime) update.datetime = new Date(req.body.datetime);
  if (req.body.type) update.type = req.body.type;
  if (req.body.status) update.status = req.body.status;

  const appointment = await Appointment.findByIdAndUpdate(req.params.id, update, { new: true });

  if (!appointment) {
    return res.status(404).json({ error: "Appointment not found" });
  }

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "RECORD_ACCESS",
    appointmentId: appointment._id.toString(),
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "RECORD_ACCESS",
    details: {
      data_accessed: `Updated appointment for ${appointment.patient_name}`,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ appointment, tx_hash: txHash });
});

router.delete("/appointments/:id", async (req, res) => {
  const ipAddress = getClientIp(req);
  const appointment = await Appointment.findByIdAndUpdate(
    req.params.id,
    { status: "Cancelled" },
    { new: true }
  );

  if (!appointment) {
    return res.status(404).json({ error: "Appointment not found" });
  }

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "RECORD_ACCESS",
    appointmentId: appointment._id.toString(),
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "RECORD_ACCESS",
    details: {
      data_accessed: `Cancelled appointment for ${appointment.patient_name}`,
      hospital_name: req.user.hospitalName,
      post: req.user.post,
    },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({ appointment, tx_hash: txHash });
});

export default router;
