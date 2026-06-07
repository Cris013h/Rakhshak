import crypto from "crypto";

const ALGORITHM = "aes-256-cbc";

function getSecretKey() {
  const key = process.env.AES_SECRET_KEY;
  if (!key) {
    throw new Error("AES_SECRET_KEY is required in .env");
  }
  if (key.length === 32) {
    return Buffer.from(key, "utf8");
  }
  return crypto.createHash("sha256").update(key).digest();
}

export function encryptAES(plaintext) {
  if (plaintext === null || plaintext === undefined) return "";
  const text = String(plaintext);
  if (text === "") return "";

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, getSecretKey(), iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return `${iv.toString("hex")}:${encrypted}`;
}

export function decryptAES(storedValue) {
  if (!storedValue || typeof storedValue !== "string") return "";
  if (!storedValue.includes(":")) return storedValue;

  const colonIndex = storedValue.indexOf(":");
  const ivHex = storedValue.slice(0, colonIndex);
  const encryptedHex = storedValue.slice(colonIndex + 1);

  if (!ivHex || !encryptedHex) return storedValue;

  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, getSecretKey(), iv);
  let decrypted = decipher.update(encryptedHex, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

export function isEncrypted(value) {
  if (!value || typeof value !== "string") return false;
  const colonIndex = value.indexOf(":");
  if (colonIndex !== 32) return false;
  const ivHex = value.slice(0, colonIndex);
  return /^[0-9a-f]{32}$/.test(ivHex);
}
