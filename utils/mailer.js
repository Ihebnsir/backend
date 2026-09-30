var emailTemplates = require('./emailTemplates');

var RESEND_API_URL = 'https://api.resend.com/emails';
var RESEND_TIMEOUT_MS = 10000;

var requiredSettings = ['RESEND_API_KEY', 'EMAIL_FROM'];
var missingSettings = requiredSettings.filter(function(name) {
  return !process.env[name] || !process.env[name].trim();
});
var emailEnabled = missingSettings.length === 0;

if (!emailEnabled) {
  console.warn('Email désactivé : variables manquantes dans .env (' + missingSettings.join(', ') + ').');
}

async function sendEmail(to, subject, html) {
  if (!emailEnabled) return false;

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

    var response = await fetch(RESEND_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + process.env.RESEND_API_KEY.trim(),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: from,
        to: [to],
        subject: subject,
        html: messageHtml
      }),
      signal: AbortSignal.timeout(RESEND_TIMEOUT_MS)
    });

    if (!response.ok) {
      var details = '';
      try {
        var body = await response.json();
        details = body && body.message ? ' : ' + body.message : '';
      } catch (parseError) {
        // Corps de réponse non JSON : on garde uniquement le statut HTTP.
      }
      console.error('Échec de l’envoi de l’email via Resend (HTTP ' + response.status + ')' + details);
      return false;
    }

    return true;
  } catch (error) {
    console.error('Échec de l’envoi de l’email via Resend : ' + (error && error.name === 'TimeoutError' ? 'délai dépassé' : error.message));
    return false;
  }
}

module.exports = { sendEmail: sendEmail };
