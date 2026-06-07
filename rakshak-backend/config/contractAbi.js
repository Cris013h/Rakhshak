export const CONTRACT_ABI = [
  "function verifyStaff(string hospitalName, string post, string idNumber, bytes32 passwordHash) returns (bool)",
  "function logDataAccess(string idNumber, string hospitalName, string post, string dataType)",
  "function logSuspiciousActivity(string idNumber, string activityType)",
  "function registerStaff(string hospitalName, string post, string idNumber, bytes32 passwordHash)",
  "function staffExists(string idNumber) view returns (bool)",
  "event LoginAttempt(string idNumber, string hospitalName, bool success, uint256 timestamp)",
  "event DataAccessed(string idNumber, string hospitalName, string post, string dataType, uint256 timestamp)",
  "event SuspiciousActivity(string idNumber, string activityType, uint256 timestamp)",
];
