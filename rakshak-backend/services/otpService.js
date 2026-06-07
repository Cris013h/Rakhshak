import bcrypt from "bcrypt";
import crypto from "crypto";
import { OTPLog } from "../models/OTPLog.js";

const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES) || 5;
const MAX_OTP_ATTEMPTS = 3;

export function generateOTP() {
  return String(crypto.randomInt(100000, 999999));
}

export async function createOTP(idNumber, purpose = "login") {
  const otp = generateOTP();
  const otpHash = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

  await OTPLog.updateMany(
    { idNumber: idNumber.toUpperCase(), purpose, used: false },
    { used: true }
  );

  await OTPLog.create({
    idNumber: idNumber.toUpperCase(),
    otpHash,
    purpose,
    expiresAt,
    used: false,
    attempts: 0,
  });

  return { otp, expiresAt };
}

export async function verifyOTP(idNumber, otp, purpose = "login") {
  const normalizedId = idNumber.toUpperCase();
  const record = await OTPLog.findOne({
    idNumber: normalizedId,
    purpose,
    used: false,
    expiresAt: { $gt: new Date() },
  }).sort({ createdAt: -1 });

  if (!record) {
    return { valid: false, reason: "OTP expired or not found" };
  }

  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    record.used = true;
    await record.save();
    return { valid: false, reason: "Too many failed attempts", locked: true };
  }

  const matches = await bcrypt.compare(otp, record.otpHash);

  if (!matches) {
    record.attempts += 1;
    if (record.attempts >= MAX_OTP_ATTEMPTS) {
      record.used = true;
    }
    await record.save();
    return {
      valid: false,
      reason: "Invalid OTP",
      attemptsLeft: MAX_OTP_ATTEMPTS - record.attempts,
      locked: record.attempts >= MAX_OTP_ATTEMPTS,
    };
  }

  record.used = true;
  await record.save();
  return { valid: true };
}

export function getOTPExpiryMinutes() {
  return OTP_EXPIRY_MINUTES;
}
