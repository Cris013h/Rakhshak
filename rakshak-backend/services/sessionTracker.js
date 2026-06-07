const activeSessions = new Map();

export function addSession(tokenJti, idNumber) {
  activeSessions.set(tokenJti, { idNumber, startedAt: Date.now() });
}

export function removeSession(tokenJti) {
  activeSessions.delete(tokenJti);
}

export function getInMemorySessionCount() {
  return activeSessions.size;
}

export function removeSessionsByIdNumber(idNumber) {
  for (const [token, session] of activeSessions.entries()) {
    if (session.idNumber === idNumber) {
      activeSessions.delete(token);
    }
  }
}
