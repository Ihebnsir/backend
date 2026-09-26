var nodemailer = require('nodemailer');

var requiredSettings = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASSWORD', 'EMAIL_FROM'];
var missingSettings = requiredSettings.filter(function(name) {
  return !process.env[name] || !process.env[name].trim();
});
var smtpPort = Number(process.env.SMTP_PORT);
var transporter = null;

if (missingSettings.length) {
  console.warn('Email désactivé : variables SMTP manquantes dans .env (' + missingSettings.join(', ') + ').');
} else if (!Number.isInteger(smtpPort) || smtpPort < 1 || smtpPort > 65535) {
  console.warn('Email désactivé : SMTP_PORT doit être un numéro de port valide.');
} else {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: smtpPort,
    secure: process.env.SMTP_SECURE.toLowerCase() === 'true' || process.env.SMTP_SECURE === '1',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  });
}

async function sendEmail(to, subject, html) {
  if (!transporter) return false;

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: to,
      subject: subject,
      html: html
    });
    return true;
  } catch (error) {
    console.error('Échec de l’envoi de l’email. Vérifiez la configuration SMTP.');
    return false;
  }
}

module.exports = { sendEmail: sendEmail };