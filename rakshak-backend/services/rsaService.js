import forge from "node-forge";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = path.join(__dirname, "..", "keys");
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, "public.pem");
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, "private.pem");

let cachedKeys = null;

function loadOrGenerateKeys() {
  if (cachedKeys) return cachedKeys;

  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true });
  }

  if (fs.existsSync(PUBLIC_KEY_PATH) && fs.existsSync(PRIVATE_KEY_PATH)) {
    cachedKeys = {
      publicKey: fs.readFileSync(PUBLIC_KEY_PATH, "utf8"),
      privateKey: fs.readFileSync(PRIVATE_KEY_PATH, "utf8"),
    };
    return cachedKeys;
  }

  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const publicPem = forge.pki.publicKeyToPem(keypair.publicKey);
  const privatePem = forge.pki.privateKeyToPem(keypair.privateKey);

  fs.writeFileSync(PUBLIC_KEY_PATH, publicPem, "utf8");
  fs.writeFileSync(PRIVATE_KEY_PATH, privatePem, "utf8");

  cachedKeys = { publicKey: publicPem, privateKey: privatePem };
  console.log("RSA 2048-bit key pair generated and stored in keys/");
  return cachedKeys;
}

export function initRSAKeys() {
  return loadOrGenerateKeys();
}

export function getPublicKey() {
  return loadOrGenerateKeys().publicKey;
}

export function decryptRSA(encryptedData) {
  if (!encryptedData || typeof encryptedData !== "string") {
    throw new Error("Invalid encrypted data");
  }

  const { privateKey } = loadOrGenerateKeys();
  const privateKeyForge = forge.pki.privateKeyFromPem(privateKey);

  try {
    const encryptedBytes = forge.util.decode64(encryptedData);
    return privateKeyForge.decrypt(encryptedBytes, "RSAES-PKCS1-V1_5");
  } catch (err) {
    throw new Error(`RSA decryption failed: ${err.message}`);
  }
}
