import jwt from "jsonwebtoken";
import { Session } from "../models/Session.js";

export function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    req.token = token;
    next();
  } catch {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.post) && req.user?.post !== "Admin") {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

export function requireAdmin(req, res, next) {
  if (req.user?.post !== "Admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

export function getClientIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "";
}

export async function getActiveSessionCount() {
  return Session.countDocuments({ active: true, expires_at: { $gt: new Date() } });
}
