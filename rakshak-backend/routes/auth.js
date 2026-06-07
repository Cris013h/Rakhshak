import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { Staff } from "../models/Staff.js";
import { PreRegisteredStaff } from "../models/PreRegisteredStaff.js";
import { AuditLog } from "../models/AuditLog.js";
import { Session } from "../models/Session.js";
import { authenticateToken, getClientIp } from "../middleware/auth.js";
import {
  hashPasswordForChain,
  generateTxHash,
  verifyStaffOnChain,
  isBlockchainEnabled,
  checkPreRegisteredOnChain,
  getPreRegisteredDetailsOnChain,
  activateStaffOnChain,
  getBlockchainStatus,
  logSuspiciousActivityOnChain,
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
import { getPublicKey, decryptRSA } from "../services/rsaService.js";
import { createOTP, verifyOTP, getOTPExpiryMinutes } from "../services/otpService.js";
import { sendOTPEmail, sendAccountActivatedEmail, maskEmail } from "../services/emailService.js";
import {
  validatePassword,
  checkPasswordHistory,
  addPasswordToHistory,
  hashPasswordBcrypt,
  verifyPasswordBcrypt,
  isPasswordExpired,
} from "../services/passwordPolicy.js";
import { setupStaffSignatureKeys } from "../services/signatureService.js";

const router = express.Router();

function parseCredentials(req) {
  if (req.body.encrypted) {
    const decryptedJson = decryptRSA(req.body.encrypted);
    return JSON.parse(decryptedJson);
  }
  return req.body;
}

async function findStaffByLogin(login, hospitalName) {
  const normalized = login.trim().toUpperCase();
  let staff = await Staff.findOne({ id_number: normalized, hospital_name: hospitalName?.trim() });
  if (!staff) {
    staff = await Staff.findOne({ username: login.trim().toLowerCase(), hospital_name: hospitalName?.trim() });
  }
  if (!staff && !hospitalName) {
    staff = await Staff.findOne({ id_number: normalized });
    if (!staff) staff = await Staff.findOne({ username: login.trim().toLowerCase() });
  }
  return staff;
}

function issueTokens(staff, ipAddress) {
  const jti = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

  const token = jwt.sign(
    {
      jti,
      idNumber: staff.id_number,
      username: staff.username || "",
      fullName: staff.full_name || staff.id_number,
      hospitalName: staff.hospital_name,
      post: staff.post,
      ward: staff.ward || "",
      passwordMustChange: staff.password_must_change || false,
    },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  const refreshToken = jwt.sign(
    { jti, idNumber: staff.id_number, type: "refresh" },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  return { token, refreshToken, jti, expiresAt };
}

router.get("/public-key", (_req, res) => {
  try {
    return res.json({ publicKey: getPublicKey() });
  } catch (err) {
    console.error("Public key error:", err);
    return res.status(500).json({ error: "Failed to load public key" });
  }
});

router.get("/blockchain-status", async (_req, res) => {
  try {
    return res.json(await getBlockchainStatus());
  } catch {
    return res.json({ connected: false, blockNumber: 0, enabled: false });
  }
});

router.get("/check-username/:username", async (req, res) => {
  const username = req.params.username.trim().toLowerCase();
  if (username.length < 6) {
    return res.json({ available: false, reason: "Minimum 6 characters" });
  }
  const existing = await Staff.findOne({ username });
  return res.json({ available: !existing });
});

router.post("/login-step1", async (req, res) => {
  const ipAddress = getClientIp(req);
  let credentials;

  try {
    credentials = parseCredentials(req);
  } catch (err) {
    return res.status(400).json({ error: "Invalid encrypted credentials. Decryption failed." });
  }

  const { hospitalName, post, login, idNumber, password } = credentials;
  const loginField = login || idNumber;

  if (!loginField || !password) {
    return res.status(400).json({ error: "Login and password are required" });
  }

  const staff = await findStaffByLogin(loginField, hospitalName);

  if (!staff || !staff.is_active) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (!staff.is_verified) {
    return res.status(403).json({ error: "Account not activated. Complete signup first." });
  }

  if (isAccountLocked(staff)) {
    return res.status(423).json({ error: buildLockoutMessage(staff.locked_until), lockedUntil: staff.locked_until });
  }

  if (clearExpiredLock(staff)) await staff.save();

  const passwordValid = await verifyPasswordBcrypt(password, staff.password_hash);
  const postMatch = !post || staff.post === post;

  let blockchainVerified = false;
  if (passwordValid && postMatch && isBlockchainEnabled()) {
    blockchainVerified = await verifyStaffOnChain({
      hospitalName: staff.hospital_name,
      post: staff.post,
      idNumber: staff.id_number,
      password,
    });
  } else if (passwordValid && postMatch) {
    blockchainVerified = true;
  }

  const valid = passwordValid && postMatch;

  await AuditLog.create({
    staff_id: staff.id_number,
    action: valid ? "LOGIN_STEP1" : "LOGIN",
    details: { hospital_name: staff.hospital_name, post: staff.post, success: valid, blockchain_verified: blockchainVerified },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: staff.id_number, action: "LOGIN_STEP1", success: valid, ipAddress }),
  });

  if (!valid) {
    const { locked } = applyFailedAttempt(staff);
    if (locked) {
      await staff.save();
      return res.status(423).json({ error: `Account locked. Try again in ${LOCKOUT_MINUTES} minutes.` });
    }
    await staff.save();
    return res.status(401).json({ error: "Invalid credentials" });
  }

  resetLockout(staff);
  await staff.save();

  const { otp, expiresAt } = await createOTP(staff.id_number, "login");
  await sendOTPEmail({ to: staff.email, name: staff.full_name || staff.id_number, otp });

  return res.json({
    message: "OTP sent",
    idNumber: staff.id_number,
    maskedEmail: maskEmail(staff.email),
    expiresAt,
    otpExpiryMinutes: getOTPExpiryMinutes(),
    devOtp: process.env.NODE_ENV !== "production" && !process.env.EMAIL_USER?.includes("@") ? otp : undefined,
  });
});

router.post("/login-step2", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { idNumber, otp } = req.body;

  if (!idNumber || !otp) {
    return res.status(400).json({ error: "ID number and OTP are required" });
  }

  const normalizedId = idNumber.trim().toUpperCase();
  const staff = await Staff.findOne({ id_number: normalizedId });

  if (!staff) {
    return res.status(404).json({ error: "Staff not found" });
  }

  const otpResult = await verifyOTP(normalizedId, otp, "login");

  if (!otpResult.valid) {
    const txHash = generateTxHash({ staffId: normalizedId, action: "FAILED_OTP", ipAddress });
    const chainTx = await logSuspiciousActivityOnChain({
      idNumber: normalizedId,
      activityType: `FAILED_OTP: ${otpResult.reason}`,
    });

    await AuditLog.create({
      staff_id: normalizedId,
      action: "FAILED_OTP",
      details: { reason: otpResult.reason, attemptsLeft: otpResult.attemptsLeft },
      ip_address: ipAddress,
      tx_hash: chainTx || txHash,
    });

    if (otpResult.locked) {
      staff.locked_until = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
      await staff.save();
      return res.status(423).json({ error: "Too many failed OTP attempts. Account locked." });
    }

    return res.status(401).json({ error: otpResult.reason, attemptsLeft: otpResult.attemptsLeft });
  }

  staff.last_login = new Date();
  staff.password_must_change = isPasswordExpired(staff.password_changed_at);
  await staff.save();

  const { token, refreshToken, jti, expiresAt } = issueTokens(staff, ipAddress);

  await Session.create({
    staff_id: normalizedId,
    token_jti: jti,
    active: true,
    expires_at: expiresAt,
    ip_address: ipAddress,
  });

  addSession(jti, normalizedId);

  res.cookie("rakshak_refresh", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  const txHash = generateTxHash({ staffId: normalizedId, action: "LOGIN", success: true, ipAddress });

  await AuditLog.create({
    staff_id: normalizedId,
    action: "LOGIN",
    details: { hospital_name: staff.hospital_name, post: staff.post, success: true },
    ip_address: ipAddress,
    tx_hash: txHash,
  });

  return res.json({
    token,
    user: {
      idNumber: staff.id_number,
      username: staff.username,
      fullName: staff.full_name || staff.id_number,
      hospitalName: staff.hospital_name,
      post: staff.post,
      ward: staff.ward || "",
      email: staff.email,
      passwordMustChange: staff.password_must_change,
    },
    blockchainVerified: true,
    rsaDecrypted: Boolean(req.body.encrypted),
    txHash,
  });
});

router.post("/verify-identity", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { idNumber, fullName, post, hospitalName } = req.body;

  if (!idNumber || !fullName || !post || !hospitalName) {
    return res.status(400).json({ error: "All identity fields are required" });
  }

  const normalizedId = idNumber.trim().toUpperCase();

  const chainStatus = await checkPreRegisteredOnChain(normalizedId);
  const preReg = await PreRegisteredStaff.findOne({ idNumber: normalizedId });

  if (!chainStatus.exists && !preReg) {
    return res.status(404).json({ error: "Not registered. Contact admin." });
  }

  if (chainStatus.activated || (preReg && preReg.status === "active")) {
    return res.status(409).json({ error: "Account already exists. Please login." });
  }

  const chainDetails = await getPreRegisteredDetailsOnChain(normalizedId);
  const details = chainDetails || preReg;

  if (!details) {
    return res.status(404).json({ error: "Pre-registration not found" });
  }

  const nameMatch = details.fullName?.toLowerCase() === fullName.trim().toLowerCase();
  const postMatch = details.post?.toLowerCase() === post.trim().toLowerCase();
  const hospitalMatch = details.hospitalName?.toLowerCase() === hospitalName.trim().toLowerCase();

  await AuditLog.create({
    staff_id: normalizedId,
    action: "IDENTITY_VERIFICATION_ATTEMPT",
    details: { success: nameMatch && postMatch && hospitalMatch },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: normalizedId, action: "IDENTITY_VERIFICATION_ATTEMPT", ipAddress }),
  });

  if (!nameMatch || !postMatch || !hospitalMatch) {
    return res.status(401).json({ error: "Details do not match our records." });
  }

  const email = preReg?.email || "";
  const verificationToken = jwt.sign(
    { idNumber: normalizedId, purpose: "signup", email },
    process.env.JWT_SECRET,
    { expiresIn: "10m" }
  );

  return res.json({
    verified: true,
    email: maskEmail(email),
    department: details.department || preReg?.department || "",
    verificationToken,
  });
});

router.post("/signup", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { verificationToken, username, email, password, confirmPassword } = req.body;

  if (!verificationToken || !username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  let payload;
  try {
    payload = jwt.verify(verificationToken, process.env.JWT_SECRET);
    if (payload.purpose !== "signup") throw new Error("Invalid token");
  } catch {
    return res.status(401).json({ error: "Verification expired. Start again." });
  }

  const idNumber = payload.idNumber;
  const preReg = await PreRegisteredStaff.findOne({ idNumber });

  if (!preReg || preReg.status !== "pending") {
    return res.status(400).json({ error: "Invalid signup state" });
  }

  if (email.toLowerCase().trim() !== preReg.email.toLowerCase().trim()) {
    return res.status(400).json({ error: "Email does not match pre-registered email" });
  }

  const existingUser = await Staff.findOne({ username: username.toLowerCase() });
  if (existingUser) {
    return res.status(409).json({ error: "Username already taken" });
  }

  const policy = validatePassword(password, { idNumber, hospitalName: preReg.hospitalName, username });
  if (!policy.valid) {
    return res.status(400).json({ error: "Password does not meet policy", details: policy.errors });
  }

  const historyCheck = await checkPasswordHistory(idNumber, password);
  if (!historyCheck.allowed) {
    return res.status(400).json({ error: historyCheck.reason });
  }

  const passwordHash = await hashPasswordBcrypt(password);
  const chainTx = await activateStaffOnChain(idNumber, password);
  const { publicKey, encryptedPrivateKey } = await setupStaffSignatureKeys(idNumber);

  await Staff.create({
    hospital_name: preReg.hospitalName,
    post: preReg.post,
    id_number: idNumber,
    username: username.toLowerCase(),
    email: preReg.email,
    full_name: preReg.fullName,
    department: preReg.department,
    phone: preReg.phone,
    password_hash: passwordHash,
    rsa_public_key: publicKey,
    rsa_private_key_encrypted: encryptedPrivateKey,
    password_changed_at: new Date(),
    is_active: true,
    is_verified: false,
  });

  preReg.status = "active";
  preReg.activatedAt = new Date();
  preReg.blockchainTxHash = chainTx || "";
  await preReg.save();

  await addPasswordToHistory(idNumber, passwordHash);

  const { otp } = await createOTP(idNumber, "signup");
  await sendOTPEmail({ to: preReg.email, name: preReg.fullName, otp });

  await AuditLog.create({
    staff_id: idNumber,
    action: "STAFF_SIGNUP",
    details: { username, hospital_name: preReg.hospitalName },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: idNumber, action: "STAFF_SIGNUP", ipAddress }),
  });

  return res.json({
    success: true,
    message: "OTP sent",
    idNumber,
    maskedEmail: maskEmail(preReg.email),
    devOtp: process.env.NODE_ENV !== "production" ? otp : undefined,
  });
});

router.post("/resend-signup-otp", async (req, res) => {
  const { idNumber } = req.body;
  if (!idNumber) return res.status(400).json({ error: "ID number required" });

  const normalizedId = idNumber.trim().toUpperCase();
  const staff = await Staff.findOne({ id_number: normalizedId });
  if (!staff) return res.status(404).json({ error: "Staff not found" });

  const { otp } = await createOTP(normalizedId, "signup");
  await sendOTPEmail({ to: staff.email, name: staff.full_name || normalizedId, otp });

  return res.json({
    message: "OTP resent",
    maskedEmail: maskEmail(staff.email),
    devOtp: process.env.NODE_ENV !== "production" ? otp : undefined,
  });
});

router.post("/verify-signup-otp", async (req, res) => {
  const ipAddress = getClientIp(req);
  const { idNumber, otp } = req.body;

  if (!idNumber || !otp) {
    return res.status(400).json({ error: "ID number and OTP required" });
  }

  const normalizedId = idNumber.trim().toUpperCase();
  const otpResult = await verifyOTP(normalizedId, otp, "signup");

  if (!otpResult.valid) {
    return res.status(401).json({ error: otpResult.reason });
  }

  const staff = await Staff.findOne({ id_number: normalizedId });
  if (!staff) {
    return res.status(404).json({ error: "Staff not found" });
  }

  staff.is_verified = true;
  await staff.save();

  await sendAccountActivatedEmail({ to: staff.email, fullName: staff.full_name });

  await AuditLog.create({
    staff_id: normalizedId,
    action: "STAFF_ACTIVATED",
    details: { hospital_name: staff.hospital_name },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: normalizedId, action: "STAFF_ACTIVATED", ipAddress }),
  });

  return res.json({ success: true, redirectTo: "/login" });
});

router.post("/change-password", authenticateToken, async (req, res) => {
  const ipAddress = getClientIp(req);
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: "All fields required" });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match" });
  }

  const staff = await Staff.findOne({ id_number: req.user.idNumber });
  if (!staff) {
    return res.status(404).json({ error: "Staff not found" });
  }

  const currentValid = await verifyPasswordBcrypt(currentPassword, staff.password_hash);
  if (!currentValid) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  const policy = validatePassword(newPassword, {
    idNumber: staff.id_number,
    hospitalName: staff.hospital_name,
    username: staff.username,
  });
  if (!policy.valid) {
    return res.status(400).json({ error: "Password does not meet policy", details: policy.errors });
  }

  const historyCheck = await checkPasswordHistory(staff.id_number, newPassword);
  if (!historyCheck.allowed) {
    return res.status(400).json({ error: historyCheck.reason });
  }

  await addPasswordToHistory(staff.id_number, staff.password_hash);

  const newHash = await hashPasswordBcrypt(newPassword);
  staff.password_hash = newHash;
  staff.password_changed_at = new Date();
  staff.password_must_change = false;
  await staff.save();

  const chainHash = hashPasswordForChain(newPassword);
  if (isBlockchainEnabled()) {
    await activateStaffOnChain(staff.id_number, newPassword);
  }

  await AuditLog.create({
    staff_id: staff.id_number,
    action: "PASSWORD_CHANGED",
    details: { hospital_name: staff.hospital_name },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: staff.id_number, action: "PASSWORD_CHANGED", ipAddress }),
  });

  return res.json({ success: true, message: "Password changed successfully" });
});

router.post("/logout", authenticateToken, async (req, res) => {
  const ipAddress = getClientIp(req);

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "LOGOUT",
    details: { hospital_name: req.user.hospitalName, post: req.user.post },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: req.user.idNumber, action: "LOGOUT", ipAddress }),
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
  if (!refreshToken) return res.status(401).json({ error: "Refresh token required" });

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_SECRET);
    if (payload.type !== "refresh") return res.status(403).json({ error: "Invalid refresh token" });

    const session = await Session.findOne({ token_jti: payload.jti, active: true, expires_at: { $gt: new Date() } });
    if (!session) return res.status(403).json({ error: "Session expired" });

    const staff = await Staff.findOne({ id_number: payload.idNumber });
    if (!staff) return res.status(404).json({ error: "Staff not found" });

    const { token } = issueTokens(staff, getClientIp(req));
    addSession(payload.jti, staff.id_number);

    return res.json({
      token,
      user: {
        idNumber: staff.id_number,
        username: staff.username,
        fullName: staff.full_name || staff.id_number,
        hospitalName: staff.hospital_name,
        post: staff.post,
        ward: staff.ward || "",
        passwordMustChange: staff.password_must_change,
      },
    });
  } catch {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
});

router.post("/session-timeout", authenticateToken, async (req, res) => {
  const ipAddress = getClientIp(req);

  await AuditLog.create({
    staff_id: req.user.idNumber,
    action: "SESSION_TIMEOUT",
    details: { hospital_name: req.user.hospitalName, post: req.user.post },
    ip_address: ipAddress,
    tx_hash: generateTxHash({ staffId: req.user.idNumber, action: "SESSION_TIMEOUT", ipAddress }),
  });

  if (req.user.jti) {
    await Session.updateOne({ token_jti: req.user.jti }, { active: false });
    removeSession(req.user.jti);
  }

  res.clearCookie("rakshak_refresh");
  return res.json({ message: "Session timeout logged" });
});

export default router;
