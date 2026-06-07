import nodemailer from "nodemailer";

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;

  if (!user || !pass || user.includes("your_gmail")) {
    return null;
  }

  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user, pass },
  });

  return transporter;
}

export function isEmailConfigured() {
  return Boolean(getTransporter());
}

export async function sendOTPEmail({ to, name, otp }) {
  const transport = getTransporter();
  if (!transport) {
    console.log(`[EMAIL DEV] OTP for ${to}: ${otp}`);
    return { sent: false, devMode: true };
  }

  await transport.sendMail({
    from: `"RAKSHAK Security" <${process.env.EMAIL_USER}>`,
    to,
    subject: "RAKSHAK — Your Login OTP",
    text: `Dear ${name},

Your one-time password for RAKSHAK login is:

${otp}

This code expires in 5 minutes.
If you did not request this, contact admin immediately.

— RAKSHAK Security System`,
  });

  return { sent: true };
}

export async function sendWelcomeEmail({ to, fullName, idNumber, post, hospitalName }) {
  const transport = getTransporter();
  const signupUrl = process.env.FRONTEND_URL || "http://localhost:5173";

  const body = `Dear ${fullName},

You have been registered on RAKSHAK Healthcare Security System by your hospital administrator.

To complete your registration visit:
${signupUrl}/signup

You will need:
• Your ID Card Number: ${idNumber}
• Your Full Name: ${fullName}
• Your Post: ${post}
• Your Hospital: ${hospitalName}

This link is valid for 48 hours.

— RAKSHAK Security Team`;

  if (!transport) {
    console.log(`[EMAIL DEV] Welcome email to ${to}:\n${body}`);
    return { sent: false, devMode: true };
  }

  await transport.sendMail({
    from: `"RAKSHAK Security" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Welcome to RAKSHAK — Complete Your Registration",
    text: body,
  });

  return { sent: true };
}

export async function sendAccountActivatedEmail({ to, fullName }) {
  const transport = getTransporter();
  const loginUrl = process.env.FRONTEND_URL || "http://localhost:5173";

  const body = `Dear ${fullName},

Your RAKSHAK account is now active.
You can login at ${loginUrl}

— RAKSHAK Security Team`;

  if (!transport) {
    console.log(`[EMAIL DEV] Activation email to ${to}:\n${body}`);
    return { sent: false, devMode: true };
  }

  await transport.sendMail({
    from: `"RAKSHAK Security" <${process.env.EMAIL_USER}>`,
    to,
    subject: "RAKSHAK — Account Activated",
    text: body,
  });

  return { sent: true };
}

export function maskEmail(email) {
  if (!email || !email.includes("@")) return "***@***";
  const [local, domain] = email.split("@");
  const masked = local.length <= 2 ? `${local[0]}***` : `${local[0]}${"*".repeat(Math.min(local.length - 1, 3))}`;
  return `${masked}@${domain}`;
}
