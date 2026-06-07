import crypto from "crypto";
import { ethers } from "ethers";
import { CONTRACT_ABI } from "../config/contractAbi.js";

let contract = null;
let provider = null;

function getContract() {
  if (contract) return contract;

  const address = process.env.CONTRACT_ADDRESS;
  const rpcUrl = process.env.RPC_URL;
  const privateKey = process.env.PRIVATE_KEY;

  if (!address || !rpcUrl || !privateKey || address.includes("<")) {
    return null;
  }

  provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  contract = new ethers.Contract(address, CONTRACT_ABI, wallet);
  return contract;
}

export function generateTxHash(data) {
  const payload = JSON.stringify({
    ...data,
    nonce: crypto.randomBytes(16).toString("hex"),
    timestamp: Date.now(),
  });
  return "0x" + crypto.createHash("sha256").update(payload).digest("hex");
}

export function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export function hashPasswordForChain(password) {
  return ethers.keccak256(ethers.toUtf8Bytes(password));
}

export function hashEmailForChain(email) {
  return ethers.keccak256(ethers.toUtf8Bytes(email.toLowerCase().trim()));
}

export async function verifyStaffOnChain({ hospitalName, post, idNumber, password }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const passwordHash = hashPasswordForChain(password);
    return await chainContract.verifyStaff(hospitalName, post, idNumber, passwordHash);
  } catch (err) {
    console.error("Blockchain verifyStaff failed:", err.message);
    return false;
  }
}

export async function preRegisterStaffOnChain({ fullName, idNumber, post, hospitalName, department, email }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const emailHash = hashEmailForChain(email);
    const tx = await chainContract.preRegisterStaff(fullName, idNumber, post, hospitalName, department, emailHash);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain preRegisterStaff failed:", err.message);
    return null;
  }
}

export async function checkPreRegisteredOnChain(idNumber) {
  const chainContract = getContract();
  if (!chainContract) return { exists: false, activated: false };

  try {
    const [exists, activated] = await chainContract.checkPreRegistered(idNumber);
    return { exists, activated };
  } catch (err) {
    console.error("Blockchain checkPreRegistered failed:", err.message);
    return { exists: false, activated: false };
  }
}

export async function getPreRegisteredDetailsOnChain(idNumber) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const [fullName, post, hospitalName, department] = await chainContract.getPreRegisteredDetails(idNumber);
    return { fullName, post, hospitalName, department };
  } catch (err) {
    console.error("Blockchain getPreRegisteredDetails failed:", err.message);
    return null;
  }
}

export async function activateStaffOnChain(idNumber, password) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const passwordHash = hashPasswordForChain(password);
    const tx = await chainContract.activateStaff(idNumber, passwordHash);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain activateStaff failed:", err.message);
    return null;
  }
}

export async function registerStaffOnChain({ hospitalName, post, idNumber, password }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const passwordHash = hashPasswordForChain(password);
    const tx = await chainContract.registerStaff(hospitalName, post, idNumber, passwordHash);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain registerStaff failed:", err.message);
    return null;
  }
}

export async function storePublicKeyOnChain(idNumber, publicKey) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const tx = await chainContract.storePublicKey(idNumber, publicKey);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain storePublicKey failed:", err.message);
    return null;
  }
}

export async function getPublicKeyFromChain(idNumber) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const key = await chainContract.getPublicKey(idNumber);
    return key && key.length > 0 ? key : null;
  } catch (err) {
    console.error("Blockchain getPublicKey failed:", err.message);
    return null;
  }
}

export async function logDataAccessOnChain({ idNumber, hospitalName, post, dataType }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const tx = await chainContract.logDataAccess(idNumber, hospitalName, post, dataType);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain logDataAccess failed:", err.message);
    return null;
  }
}

export async function logSuspiciousActivityOnChain({ idNumber, activityType }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const tx = await chainContract.logSuspiciousActivity(idNumber, activityType);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain logSuspiciousActivity failed:", err.message);
    return null;
  }
}

export async function logRecordSignatureOnChain({ idNumber, recordHash, valid }) {
  const chainContract = getContract();
  if (!chainContract) return null;

  try {
    const tx = await chainContract.logRecordSignature(idNumber, recordHash, valid);
    const receipt = await tx.wait();
    return receipt.hash;
  } catch (err) {
    console.error("Blockchain logRecordSignature failed:", err.message);
    return null;
  }
}

export async function logAuditEvent({ staffId, action, details, ipAddress }) {
  const txHash = generateTxHash({ staffId, action, details, ipAddress });
  return txHash;
}

export function isBlockchainEnabled() {
  return Boolean(getContract());
}

export async function getBlockNumber() {
  const chainContract = getContract();
  if (!chainContract || !provider) {
    return null;
  }

  try {
    return await provider.getBlockNumber();
  } catch (err) {
    console.error("Failed to fetch block number:", err.message);
    return null;
  }
}

export async function getBlockchainStatus() {
  const enabled = isBlockchainEnabled();
  const blockNumber = enabled ? await getBlockNumber() : null;
  return {
    connected: enabled && blockNumber !== null,
    blockNumber: blockNumber ?? 0,
    enabled,
  };
}
