import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { Staff } from "../models/Staff.js";
import { AuditLog } from "../models/AuditLog.js";
import { Session } from "../models/Session.js";
import { authenticateToken, getClientIp } from "../middleware/auth.js";
import {
  hashPassword,
  generateTxHash,
  verifyStaffOnChain,
  isBlockchainEnabled,
} from "../services/blockchain.js";
import {
  isAccountLocked,
  clearExpiredLock,
  applyFailedAttempt,
  resetLockout,
  buildLockoutMessage,
  LOCKOUT_MINUTES,
  MAX_FAILED_ATTEMPTS,
} from "../services/lockoutService.js";
import { addSession, removeSession } from "../services/sessionTracker.js";

const router = express.Router();

router.post("/login", async (req, res) => {
  const { hospitalName, post, idNumber, password } = req.body;
  const ipAddress = getClientIp(req);

  if (!hospitalName || !post || !idNumber || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  const normalizedId = idNumber.trim().toUpperCase();

  try {
    const staff = await Staff.findOne({
      hospital_name: hospitalName.trim(),
      id_number: normalizedId,
    });

    if (!staff) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (isAccountLocked(staff)) {
      return res.status(423).json({
        error: buildLockoutMessage(staff.locked_until),
        lockedUntil: staff.locked_until,
      });
    }

    if (clearExpiredLock(staff)) {
      await staff.save();
    }

    const passwordHash = hashPassword(password);
    const valid = staff.password_hash === passwordHash && staff.post === post;

    let blockchainVerified = false;
    if (valid && isBlockchainEnabled()) {
      const chainResult = await verifyStaffOnChain({
        hospitalName: hospitalName.trim(),
        post,
        idNumber: normalizedId,
        password,
      });
      blockchainVerified = chainResult === true;
    } else if (valid) {
      blockchainVerified = true;
    }

    const txHash = generateTxHash({
      staffId: normalizedId,
      action: "LOGIN",
      success: valid,
      ipAddress,
      blockchainVerified,
    });

    await AuditLog.create({
      staff_id: normalizedId,
      action: "LOGIN",
      details: {
        hospital_name: hospitalName.trim(),
        post,
        success: valid,
        blockchain_verified: blockchainVerified,
      },
      ip_address: ipAddress,
      tx_hash: txHash,
    });

    if (!valid) {
      const { locked } = applyFailedAttempt(staff);

      if (locked) {
        const lockTxHash = generateTxHash({
          staffId: normalizedId,
          action: "LOCKOUT",
          ipAddress,
        });

        await AuditLog.create({
          staff_id: normalizedId,
          action: "LOCKOUT",
          details: {
            reason: `${MAX_FAILED_ATTEMPTS} consecutive failed login attempts`,
            locked_until: staff.locked_until,
          },
          ip_address: ipAddress,
          tx_hash: lockTxHash,
        });

        await staff.save();

        return res.status(423).json({
          error: `Account locked. Too many failed attempts. Try again in ${LOCKOUT_MINUTES} minutes.`,
          lockedUntil: staff.locked_until,
        });
      }

      await staff.save();
      return res.status(401).json({ error: "Invalid credentials" });
    }

    resetLockout(staff);
    await staff.save();

    const jti = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

    const token = jwt.sign(
      {
        jti,
        idNumber: normalizedId,
        hospitalName: hospitalName.trim(),
        post: staff.post,
        ward: staff.ward || "",
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    await Session.create({
      staff_id: normalizedId,
      token_jti: jti,
      active: true,
      expires_at: expiresAt,
      ip_address: ipAddress,
    });

    addSession(jti, normalizedId);

    const refreshToken = jwt.sign(
      { jti, idNumber: normalizedId, type: "refresh" },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("rakshak_refresh", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({
      token,
      user: {
        idNumber: normalizedId,
        hospitalName: hospitalName.trim(),
        post: staff.post,
        ward: staff.ward || "",
      },
      blockchainVerified,
      txHash,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed. Server error." });
  }
});

router.post("/logout", authenticateToken, async (req, res) => {
  const ipAddress = getClientIp(req);

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "LOGOUT",
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "LOGOUT",
    details: { hospital_name: req.user.hospitalName, post: req.user.post },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  if (req.user.jti) {
    await Session.updateOne({ token_jti: req.user.jti }, { active: false });
    removeSession(req.user.jti);
  }

  res.clearCookie("rakshak_refresh");
  return res.json({ message: "Logged out successfully" });
});

router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies?.rakshak_refresh;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token required" });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    if (payload.type !== "refresh") {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    const session = await Session.findOne({
      token_jti: payload.jti,
      active: true,
      expires_at: { $gt: new Date() },
    });

    if (!session) {
      return res.status(403).json({ error: "Session expired" });
    }

    const staff = await Staff.findOne({ id_number: payload.idNumber });
    if (!staff) {
      return res.status(404).json({ error: "Staff not found" });
    }

    const token = jwt.sign(
      {
        jti: payload.jti,
        idNumber: staff.id_number,
        hospitalName: staff.hospital_name,
        post: staff.post,
        ward: staff.ward || "",
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    addSession(payload.jti, staff.id_number);

    return res.json({
      token,
      user: {
        idNumber: staff.id_number,
        hospitalName: staff.hospital_name,
        post: staff.post,
        ward: staff.ward || "",
      },
    });
  } catch {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
});

router.post("/session-timeout", authenticateToken, async (req, res) => {
  const ipAddress = getClientIp(req);

  const txHash = generateTxHash({
    staffId: req.user.idNumber,
    action: "SESSION_TIMEOUT",
    ipAddress,
  });

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "SESSION_TIMEOUT",
    details: { hospital_name: req.user.hospitalName, post: req.user.post },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  if (req.user.jti) {
    await Session.updateOne({ token_jti: req.user.jti }, { active: false });
    removeSession(req.user.jti);
  }

  res.clearCookie("rakshak_refresh");
  return res.json({ message: "Session timeout logged" });
});

export default router;
