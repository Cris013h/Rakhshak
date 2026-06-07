const BASE_URL = "http://localhost:5000";
const ATTACKER_IP = "203.0.113.50";

const HOSPITALS = ["City General", "Metro Health", "Riverside Medical", "Summit Hospital"];
const POSTS = ["Doctor", "Nurse", "Admin", "Pharmacist", "Receptionist"];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomId() {
  return `FAKE${Math.floor(Math.random() * 9000 + 1000)}`;
}

function randomPassword() {
  return `pass${Math.random().toString(36).slice(2, 10)}`;
}

function formatStatus(statusCode) {
  if (statusCode === 429 || statusCode === 403) {
    return `${statusCode} BLOCKED`;
  }
  if (statusCode === 200) {
    return "200 OK";
  }
  return `${statusCode}`;
}

async function sendRequest({ method, path, body, index, total, label }) {
  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Forwarded-For": ATTACKER_IP,
    },
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  let statusCode = 0;
  try {
    const response = await fetch(`${BASE_URL}${path}`, options);
    statusCode = response.status;
  } catch (err) {
    console.log(`Request ${index}/${total} (${label}) → Error: ${err.message}`);
    return { statusCode: 0, blocked: false };
  }

  const blocked = statusCode === 429 || statusCode === 403;
  console.log(`Request ${index}/${total} (${label}) → Status: ${formatStatus(statusCode)}`);
  return { statusCode, blocked };
}

async function runBruteForcePhase() {
  console.log("\n=== Phase 1: Brute Force Login Attack (100 POST /api/login) ===\n");
  const results = [];

  for (let i = 1; i <= 100; i++) {
    const result = await sendRequest({
      method: "POST",
      path: "/api/login",
      body: {
        hospitalName: randomItem(HOSPITALS),
        post: randomItem(POSTS),
        idNumber: randomId(),
        password: randomPassword(),
      },
      index: i,
      total: 100,
      label: "login",
    });
    results.push(result);
  }

  return results;
}

async function runScrapingPhase() {
  console.log("\n=== Phase 2: Unauthorized Audit Log Scraping (50 GET /api/audit-logs) ===\n");
  const results = [];

  for (let i = 1; i <= 50; i++) {
    const result = await sendRequest({
      method: "GET",
      path: "/api/audit-logs",
      index: i,
      total: 50,
      label: "scrape",
    });
    results.push(result);
  }

  return results;
}

async function main() {
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║   RAKSHAK Flood Simulator — Demo Attack Script   ║");
  console.log("╚══════════════════════════════════════════════════╝");
  console.log(`Attacker IP: ${ATTACKER_IP}`);
  console.log(`Target: ${BASE_URL}\n`);

  const loginResults = await runBruteForcePhase();
  const scrapeResults = await runScrapingPhase();

  const allResults = [...loginResults, ...scrapeResults];
  const total = allResults.length;
  const blocked = allResults.filter((r) => r.blocked).length;
  const allowed = total - blocked;

  console.log("\n╔══════════════════════════════════════════════════╗");
  console.log(`║  Total Requests: ${total} | Blocked: ${blocked} | Allowed: ${allowed}`.padEnd(51) + "║");
  console.log("╚══════════════════════════════════════════════════╝\n");
}

main().catch((err) => {
  console.error("Flood simulator failed:", err.message);
  process.exit(1);
});
