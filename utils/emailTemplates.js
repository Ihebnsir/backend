function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function emailLayout(content, expiryMessage, reassuranceMessage) {
  return '<!doctype html>' +
    '<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>' +
    '<body bgcolor="#0a0e14" style="margin:0; padding:24px 12px; background-color:#0a0e14; font-family:Arial, Helvetica, sans-serif; color:#1b2937;">' +
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0a0e14" style="width:100%; background-color:#0a0e14;">' +
    '<tr><td align="center" style="padding:20px 0;">' +
    '<table role="presentation" width="480" cellpadding="0" cellspacing="0" border="0" bgcolor="#ffffff" style="width:100%; max-width:480px; margin:0 auto; background-color:#ffffff; border:1px solid #263342; border-radius:8px; overflow:hidden;">' +
    '<tr><td align="center" bgcolor="#ffffff" style="padding:30px 28px 22px; background-color:#ffffff;">' +
    '<div style="font-family:Arial, Helvetica, sans-serif; font-size:30px; line-height:36px; font-weight:700; color:#007a62;">SecuLens</div>' +
    '<div style="padding-top:5px; font-family:Arial, Helvetica, sans-serif; font-size:12px; line-height:18px; color:#647383;">Web Security Assessment Platform</div>' +
    '</td></tr>' +
    '<tr><td bgcolor="#ffffff" style="padding:8px 28px 28px; background-color:#ffffff; font-family:Arial, Helvetica, sans-serif; color:#1b2937;">' +
    content +
    '</td></tr>' +
    '<tr><td bgcolor="#f2f6f8" style="padding:18px 28px; background-color:#f2f6f8; border-top:1px solid #e1e8ed; font-family:Arial, Helvetica, sans-serif; font-size:12px; line-height:19px; color:#536273;">' +
    '<p style="margin:0 0 6px;">' + expiryMessage + '</p>' +
    '<p style="margin:0;">' + reassuranceMessage + '</p>' +
    '</td></tr>' +
    '</table>' +
    '<div style="padding-top:16px; font-family:Arial, Helvetica, sans-serif; font-size:11px; line-height:17px; color:#aab7c4;">SecuLens &bull; Web Security Assessment Platform</div>' +
    '</td></tr></table>' +
    '</body></html>';
}

function actionContent(intro, actionLabel, actionUrl, closing) {
  var safeUrl = escapeHtml(actionUrl);

  return '<p style="margin:0 0 18px; font-size:15px; line-height:24px; color:#1b2937;">' + intro + '</p>' +
    '<table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:24px auto;">' +
    '<tr><td align="center" bgcolor="#00f5a0" style="background-color:#00f5a0; border-radius:7px;">' +
    '<a href="' + safeUrl + '" style="display:inline-block; padding:14px 24px; border:1px solid #00f5a0; border-radius:7px; background-color:#00f5a0; color:#0a0e14; font-family:Arial, Helvetica, sans-serif; font-size:15px; line-height:20px; font-weight:700; text-decoration:none;">' + actionLabel + '</a>' +
    '</td></tr></table>' +
    '<p style="margin:0 0 7px; font-size:12px; line-height:18px; color:#536273;">Si le bouton ne fonctionne pas, ouvrez ce lien :</p>' +
    '<p style="margin:0 0 18px; font-family:Arial, Helvetica, sans-serif; font-size:12px; line-height:19px; word-break:break-all;">' +
    '<a href="' + safeUrl + '" style="color:#007a62; text-decoration:underline; word-break:break-all;">' + safeUrl + '</a></p>' +
    '<p style="margin:0; font-size:14px; line-height:22px; color:#1b2937;">' + closing + '</p>';
}

function welcomeEmail(actionUrl) {
  var content = actionContent(
    'Bienvenue sur SecuLens ! Votre compte est prêt : vous pouvez dès maintenant l’utiliser pour scanner des sites et examiner leur sécurité. Vérifiez votre adresse email pour confirmer votre compte.',
    'Vérifier mon adresse email',
    actionUrl,
    'Ravi de vous accueillir,<br><strong>L’équipe SecuLens</strong>'
  );

  return emailLayout(
    content,
    'Ce lien de vérification expire dans 24 heures.',
    'Si vous n’êtes pas à l’origine de cette inscription, vous pouvez ignorer cet email.'
  );
}

function passwordResetEmail(actionUrl) {
  var content = actionContent(
    'Vous avez demandé à réinitialiser le mot de passe de votre compte SecuLens. Utilisez le bouton ci-dessous pour en choisir un nouveau.',
    'Réinitialiser mon mot de passe',
    actionUrl,
    'Si vous avez demandé cette réinitialisation, suivez le lien pour continuer.'
  );

  return emailLayout(
    content,
    'Ce lien de réinitialisation expire dans 1 heure.',
    'Si vous n’êtes pas à l’origine de cette demande, ignorez cet email. Votre mot de passe ne changera pas.'
  );
}

module.exports = {
  welcomeEmail: welcomeEmail,
  passwordResetEmail: passwordResetEmail
};
