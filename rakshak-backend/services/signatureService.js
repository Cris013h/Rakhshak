import crypto from "crypto";
import { encryptAES, decryptAES } from "./aesService.js";
import { getPublicKeyFromChain, storePublicKeyOnChain } from "./blockchain.js";

const STAFF_KEYS = new Map();

export function generateKeyPair(idNumber) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const encryptedPrivateKey = encryptAES(privateKey);
  STAFF_KEYS.set(idNumber.toUpperCase(), { publicKey, privateKey });

  return { publicKey, encryptedPrivateKey };
}

export function loadStaffKeys(idNumber, encryptedPrivateKey, publicKey) {
  if (!encryptedPrivateKey || !publicKey) return;
  try {
    const privateKey = decryptAES(encryptedPrivateKey);
    STAFF_KEYS.set(idNumber.toUpperCase(), { publicKey, privateKey });
  } catch (err) {
    console.error(`Failed to load keys for ${idNumber}:`, err.message);
  }
}

function getStaffPrivateKey(idNumber, encryptedPrivateKey) {
  const normalized = idNumber.toUpperCase();
  if (STAFF_KEYS.has(normalized)) {
    return STAFF_KEYS.get(normalized).privateKey;
  }
  if (encryptedPrivateKey) {
    const privateKey = decryptAES(encryptedPrivateKey);
    STAFF_KEYS.set(normalized, { publicKey: null, privateKey });
    return privateKey;
  }
  throw new Error("No signing key available for staff member");
}

export function signRecord(idNumber, recordData, encryptedPrivateKey) {
  const privateKey = getStaffPrivateKey(idNumber, encryptedPrivateKey);
  const dataString = typeof recordData === "string" ? recordData : JSON.stringify(recordData);
  const hash = crypto.createHash("sha256").update(dataString).digest();

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(hash);
  sign.end();
  return sign.sign(privateKey, "hex");
}

export async function verifySignature(idNumber, recordData, signature, publicKeyFromDb) {
  const dataString = typeof recordData === "string" ? recordData : JSON.stringify(recordData);
  const hash = crypto.createHash("sha256").update(dataString).digest();

  let publicKey = publicKeyFromDb;
  if (!publicKey) {
    publicKey = await getPublicKeyFromChain(idNumber);
  }

  if (!publicKey) {
    return { verified: false, reason: "Public key not found" };
  }

  try {
    const verify = crypto.createVerify("RSA-SHA256");
    verify.update(hash);
    verify.end();
    const valid = verify.verify(publicKey, signature, "hex");
    return { verified: valid, reason: valid ? "Signature valid" : "Signature mismatch" };
  } catch (err) {
    return { verified: false, reason: err.message };
  }
}

export async function setupStaffSignatureKeys(idNumber) {
  const { publicKey, encryptedPrivateKey } = generateKeyPair(idNumber);
  const txHash = await storePublicKeyOnChain(idNumber, publicKey);
  return { publicKey, encryptedPrivateKey, blockchainTxHash: txHash };
}
