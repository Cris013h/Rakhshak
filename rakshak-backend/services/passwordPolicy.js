import bcrypt from "bcrypt";
import { PasswordHistory } from "../models/PasswordHistory.js";

const COMMON_PASSWORDS = [
  "password", "password123", "admin123", "admin@123", "123456", "12345678",
  "123456789", "1234567890", "qwerty", "qwerty123", "letmein", "welcome",
  "welcome1", "monkey", "dragon", "master", "login", "princess", "football",
  "shadow", "sunshine", "iloveyou", "trustno1", "baseball", "superman",
  "michael", "ninja", "mustang", "password1", "abc123", "admin", "root",
  "toor", "pass", "test", "guest", "changeme", "hello", "charlie", "donald",
  "access", "secret", "passw0rd", "p@ssw0rd", "P@ssw0rd", "Password1",
  "Password123", "Admin123", "doctor123", "nurse123", "hospital", "medical",
  "healthcare", "rakshak", "blockchain", "ethereum", "bitcoin", "crypto",
  "secure123", "security", "firewall", "encryption", "administrator",
  "user1234", "demo123", "test1234", "temp1234", "default", "changeme123",
  "welcome123", "letmein123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "1q2w3e4r", "1qaz2wsx", "qazwsx", "password12", "password1234",
  "admin1234", "admin12345", "pass1234", "pass12345", "summer2024",
  "winter2024", "spring2024", "fall2024", "january", "february",
  "march2024", "april2024", "may2024", "june2024", "july2024",
  "august2024", "september", "october", "november", "december",
  "india123", "mumbai123", "delhi123", "chennai", "bangalore",
  "hyderabad", "kolkata", "pune123", "jaipur123", "lucknow",
];

const PASSWORD_EXPIRY_DAYS = Number(process.env.PASSWORD_EXPIRY_DAYS) || 90;
const MAX_PASSWORD_HISTORY = Number(process.env.MAX_PASSWORD_HISTORY) || 5;

export function validatePassword(password, { idNumber = "", hospitalName = "", username = "" } = {}) {
  const errors = [];
  const checks = {
    minLength: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[!@#$%^&*]/.test(password),
    noIdNumber: !idNumber || !password.toLowerCase().includes(idNumber.toLowerCase()),
    noHospital: !hospitalName || !password.toLowerCase().includes(hospitalName.toLowerCase()),
    noUsername: !username || !password.toLowerCase().includes(username.toLowerCase()),
    notCommon: !COMMON_PASSWORDS.includes(password.toLowerCase()),
  };

  if (!checks.minLength) errors.push("Minimum 12 characters required");
  if (!checks.uppercase) errors.push("At least one uppercase letter required");
  if (!checks.lowercase) errors.push("At least one lowercase letter required");
  if (!checks.number) errors.push("At least one number required");
  if (!checks.special) errors.push("At least one special character (!@#$%^&*) required");
  if (!checks.noIdNumber) errors.push("Password cannot contain your ID number");
  if (!checks.noHospital) errors.push("Password cannot contain hospital name");
  if (!checks.noUsername) errors.push("Password cannot contain username");
  if (!checks.notCommon) errors.push("Password is too common");

  const passed = Object.values(checks).filter(Boolean).length;
  const strength = Math.round((passed / Object.keys(checks).length) * 100);

  return { valid: errors.length === 0, errors, checks, strength };
}

export async function checkPasswordHistory(idNumber, newPassword) {
  const history = await PasswordHistory.find({ idNumber: idNumber.toUpperCase() })
    .sort({ createdAt: -1 })
    .limit(MAX_PASSWORD_HISTORY);

  for (const entry of history) {
    const match = await bcrypt.compare(newPassword, entry.passwordHash);
    if (match) {
      return { allowed: false, reason: "Cannot reuse a recent password" };
    }
  }

  return { allowed: true };
}

export async function addPasswordToHistory(idNumber, passwordHash) {
  await PasswordHistory.create({
    idNumber: idNumber.toUpperCase(),
    passwordHash,
  });

  const all = await PasswordHistory.find({ idNumber: idNumber.toUpperCase() })
    .sort({ createdAt: -1 });

  if (all.length > MAX_PASSWORD_HISTORY) {
    const toDelete = all.slice(MAX_PASSWORD_HISTORY);
    await PasswordHistory.deleteMany({ _id: { $in: toDelete.map((d) => d._id) } });
  }
}

export function isPasswordExpired(passwordChangedAt) {
  if (!passwordChangedAt) return false;
  const expiryMs = PASSWORD_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
  return Date.now() - new Date(passwordChangedAt).getTime() > expiryMs;
}

export function getPasswordExpiryDays() {
  return PASSWORD_EXPIRY_DAYS;
}

export async function hashPasswordBcrypt(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPasswordBcrypt(password, hash) {
  if (hash.startsWith("$2")) {
    return bcrypt.compare(password, hash);
  }
  const crypto = await import("crypto");
  const shaHash = crypto.createHash("sha256").update(password).digest("hex");
  return shaHash === hash;
}
