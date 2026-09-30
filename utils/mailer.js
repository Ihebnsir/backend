var nodemailer = require('nodemailer');
var emailTemplates = require('./emailTemplates');

var requiredSettings = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'EMAIL_FROM'];
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
  // Le mode de chiffrement se déduit de SMTP_PORT (aucun port codé en dur) :
  // - port 465 : SSL/TLS implicite, la connexion est chiffrée dès le premier octet (secure: true) ;
  // - autre port (587, 2525…) : connexion en clair puis passage en TLS via la commande STARTTLS
  //   (secure: false). requireTLS: true refuse d'envoyer si le serveur ne propose pas STARTTLS,
  //   donc les identifiants et le message ne circulent jamais en clair.
  // SMTP_SECURE n'est plus utilisé : un SMTP_SECURE=true oublié avec le port 587 casserait l'envoi.
  var implicitTls = smtpPort === 465;
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: smtpPort,
    secure: implicitTls,
    requireTLS: !implicitTls,
    // Échec rapide (10 s au lieu de 2 min par défaut) pour qu'un port bloqué apparaisse vite dans les logs.
    connectionTimeout: 10000,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  });

  // Test de connexion + authentification au démarrage (aucun email envoyé) : le résultat
  // apparaît dans les logs Render et dit tout de suite si le port est bloqué (ETIMEDOUT)
  // ou si les identifiants sont refusés (EAUTH).
  transporter.verify().then(function() {
    console.log('SMTP prêt : ' + process.env.SMTP_HOST + ':' + smtpPort + ' (' + (implicitTls ? 'SSL implicite' : 'STARTTLS') + ').');
  }).catch(function(error) {
    var smtpCode = error && error.responseCode ? ', réponse SMTP ' + error.responseCode : '';
    console.error('SMTP injoignable au démarrage : ' + process.env.SMTP_HOST + ':' + smtpPort + ' (' + (error && error.code ? error.code : 'inconnu') + smtpCode + ').');
  });
}

async function sendEmail(to, subject, html) {
  if (!transporter) return false;

  try {
    var actionLink = typeof html === 'string' ? html.match(/<a\b[^>]*\bhref=["']([^"']+)["']/i) : null;
    var messageHtml = html;

    if (actionLink && subject === 'Bienvenue sur SecuLens - vérifiez votre adresse email') {
      messageHtml = emailTemplates.welcomeEmail(actionLink[1]);
    } else if (actionLink && subject === 'Réinitialisation de votre mot de passe SecuLens') {
      messageHtml = emailTemplates.passwordResetEmail(actionLink[1]);
    }

    var configuredFrom = process.env.EMAIL_FROM.trim();
    var from = configuredFrom.indexOf('<') === -1
      ? 'SecuLens <' + configuredFrom + '>'
      : configuredFrom;

    var info = await transporter.sendMail({
      from: from,
      to: to,
      subject: subject,
      html: messageHtml
    });
    // Trace de succès (sans l'adresse du destinataire) pour confirmer l'envoi dans les logs.
    console.log('Email envoyé : « ' + subject + ' » (' + (info && info.messageId ? info.messageId : 'sans identifiant') + ').');
    return true;
  } catch (error) {
    // On ne logue que le code d'erreur et le code SMTP : jamais l'objet complet,
    // qui peut contenir la configuration du transporteur (identifiants inclus).
    var errorCode = error && error.code ? error.code : 'inconnu';
    var smtpCode = error && error.responseCode ? ', réponse SMTP ' + error.responseCode : '';
    console.error('Échec de l’envoi de l’email (' + errorCode + smtpCode + '). Vérifiez la configuration SMTP.');
    return false;
  }
}

module.exports = { sendEmail: sendEmail };