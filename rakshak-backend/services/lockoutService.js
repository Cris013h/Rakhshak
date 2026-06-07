export const LOCKOUT_MINUTES = 15;
export const MAX_FAILED_ATTEMPTS = 3;

export function getRemainingLockMinutes(lockedUntil) {
  const ms = new Date(lockedUntil).getTime() - Date.now();
  return Math.max(1, Math.ceil(ms / 60000));
}

export function isAccountLocked(staff) {
  return Boolean(staff?.locked_until && staff.locked_until > new Date());
}

export function clearExpiredLock(staff) {
  if (staff.locked_until && staff.locked_until <= new Date()) {
    staff.locked_until = null;
    staff.failed_login_attempts = 0;
    return true;
  }
  return false;
}

export function applyFailedAttempt(staff) {
  staff.failed_login_attempts += 1;

  if (staff.failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
    staff.locked_until = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
    return { locked: true, attempts: staff.failed_login_attempts };
  }

  return { locked: false, attempts: staff.failed_login_attempts };
}

export function resetLockout(staff) {
  staff.failed_login_attempts = 0;
  staff.locked_until = null;
}

export function buildLockoutMessage(lockedUntil) {
  const remaining = getRemainingLockMinutes(lockedUntil);
  return `Account locked. Too many failed attempts. Try again in ${remaining} minute${remaining !== 1 ? "s" : ""}.`;
}
