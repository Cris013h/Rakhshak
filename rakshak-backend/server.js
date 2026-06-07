import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import mongoose from "mongoose";
import authRoutes from "./routes/auth.js";
import auditRoutes from "./routes/audit.js";
import adminRoutes from "./routes/admin.js";
import doctorRoutes from "./routes/doctor.js";
import nurseRoutes from "./routes/nurse.js";
import pharmacistRoutes from "./routes/pharmacist.js";
import receptionistRoutes from "./routes/receptionist.js";
import patientRoutes from "./routes/patients.js";
import { firewallMiddleware, initFirewall } from "./middleware/firewall.js";
import { initRSAKeys } from "./services/rsaService.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors({ origin: ["http://localhost:5173", "http://127.0.0.1:5173"], credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(firewallMiddleware());

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "rakshak-backend" });
});

app.use("/api", authRoutes);
app.use("/api", auditRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/doctor", doctorRoutes);
app.use("/api/nurse", nurseRoutes);
app.use("/api/pharmacist", pharmacistRoutes);
app.use("/api/receptionist", receptionistRoutes);
app.use("/api/patients", patientRoutes);

async function start() {
  try {
    initRSAKeys();
    console.log("RSA keys loaded");
    await mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/rakshak");
    console.log("MongoDB connected");
    await initFirewall();
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`RAKSHAK backend running on http://localhost:${PORT}`);
  });
}

start();
