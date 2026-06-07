import hre from "hardhat";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TEST_STAFF = [
  { hospitalName: "City General", post: "Admin", idNumber: "ADM001", password: "admin123" },
  { hospitalName: "City General", post: "Doctor", idNumber: "DOC001", password: "doc123" },
  { hospitalName: "City General", post: "Nurse", idNumber: "NRS001", password: "nurse123" },
  { hospitalName: "City General", post: "Pharmacist", idNumber: "PHA001", password: "pharma123" },
  { hospitalName: "City General", post: "Receptionist", idNumber: "REC001", password: "recep123" },
];

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const HospitalAuth = await hre.ethers.getContractFactory("HospitalAuth");
  const contract = await HospitalAuth.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("HospitalAuth deployed to:", address);

  for (const staff of TEST_STAFF) {
    const passwordHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes(staff.password));
    const tx = await contract.registerStaff(
      staff.hospitalName,
      staff.post,
      staff.idNumber,
      passwordHash
    );
    await tx.wait();
    console.log(`Registered ${staff.idNumber} (${staff.post})`);
  }

  const envPath = path.join(__dirname, "..", ".env");
  const envExamplePath = path.join(__dirname, "..", ".env.example");
  let envContent = "";

  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, "utf8");
    if (envContent.includes("CONTRACT_ADDRESS=")) {
      envContent = envContent.replace(/CONTRACT_ADDRESS=.*/g, `CONTRACT_ADDRESS=${address}`);
    } else {
      envContent += `\nCONTRACT_ADDRESS=${address}\n`;
    }
  } else if (fs.existsSync(envExamplePath)) {
    envContent = fs.readFileSync(envExamplePath, "utf8").replace(
      "CONTRACT_ADDRESS=<filled after deploy>",
      `CONTRACT_ADDRESS=${address}`
    );
  } else {
    envContent = `MONGO_URI=mongodb://localhost:27017/rakshak
JWT_SECRET=rakshak_secret_key
CONTRACT_ADDRESS=${address}
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d026dde6bfbd004fd8a8d0695982397429daf9
RPC_URL=http://127.0.0.1:8545
PORT=5000
`;
  }

  fs.writeFileSync(envPath, envContent);
  console.log("\nUpdated rakshak-backend/.env with CONTRACT_ADDRESS");

  console.log("\n=== Demo Credentials ===");
  for (const staff of TEST_STAFF) {
    console.log(
      `Hospital: "${staff.hospitalName}" | Post: ${staff.post} | ID: ${staff.idNumber} | Password: ${staff.password}`
    );
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
