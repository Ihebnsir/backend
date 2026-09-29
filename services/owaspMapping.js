// Correspondance ruleId -> catégorie OWASP Top 10 (édition 2021), utilisée uniquement pour
// l'affichage : elle ne change ni la détection ni le score.
//
// Classification MANUELLE et pédagogique. Un même CWE peut appartenir à plusieurs catégories
// OWASP selon le contexte (ex. CWE-200 est rangé par OWASP dans A01, mais un en-tête Server
// bavard relève d'abord d'une mauvaise configuration). Pour chaque règle, on retient la
// catégorie la plus représentative du problème concret détecté, pas forcément celle de la
// liste officielle des CWE.
//
// La table est indexée par ruleId (et non par CWE) : une règle comme SEC-005 produit plusieurs
// CWE (CWE-614, CWE-1004) mais décrit un seul problème, elle doit donc avoir une seule catégorie.
// C'est l'UNIQUE source de ce mapping dans le projet : ne pas le recopier dans les fichiers de règles.
//
// Volontairement absents : SEC-020 (page tronquée) et HTTP-REDIRECT, qui sont des informations
// sur le déroulement du scan et non des faiblesses de sécurité.

var categories = {
  A01: { code: 'A01:2021', name: 'Broken Access Control' },
  A02: { code: 'A02:2021', name: 'Cryptographic Failures' },
  A05: { code: 'A05:2021', name: 'Security Misconfiguration' },
  A06: { code: 'A06:2021', name: 'Vulnerable and Outdated Components' },
  A07: { code: 'A07:2021', name: 'Identification and Authentication Failures' }
};

var owaspByRuleId = {
  'SEC-001': categories.A05, // Content-Security-Policy absent
  'SEC-002': categories.A05, // X-Content-Type-Options absent
  'SEC-003': categories.A02, // Strict-Transport-Security absent : trafic non forcé en HTTPS
  'SEC-004': categories.A05, // X-Frame-Options absent (CWE-1021, rangé en A04 par OWASP, mais c'est un en-tête manquant)
  'SEC-005': categories.A05, // Cookie sans Secure / HttpOnly / SameSite
  'SEC-006': categories.A05, // En-tête Server / X-Powered-By exposé
  'SEC-007': categories.A05, // Referrer-Policy absent ou trop permissif
  'SEC-008': categories.A05, // Permissions-Policy absent
  'SEC-009': categories.A05, // Cache-Control insuffisant
  'SEC-010': categories.A05, // Cross-Origin-Opener-Policy absent
  'SEC-011': categories.A02, // Version TLS obsolète
  'SEC-012': categories.A02, // Certificat TLS bientôt expiré
  'SEC-013': categories.A02, // Certificat TLS expiré
  'SEC-014': categories.A01, // Formulaire POST sans jeton CSRF (CWE-352)
  'SEC-015': categories.A02, // Formulaire HTTPS envoyé en HTTP
  'SEC-016': categories.A05, // Lien target="_blank" sans rel="noopener"
  'SEC-017': categories.A02, // Contenu mixte HTTP sur une page HTTPS
  'SEC-018': categories.A05, // Méthodes HTTP dangereuses annoncées
  'SEC-019': categories.A05, // Fichier sensible (.env, .git) accessible : erreur de déploiement
  'SEC-021': categories.A01, // Endpoint API ou d'administration exposé sans contrôle d'accès
  'SEC-022': categories.A06, // WordPress détecté / obsolète
  'SEC-023': categories.A05, // Port TCP sensible ouvert
  'SEC-024': categories.A05, // Sous-domaine exposé à une prise de contrôle (DNS orphelin)
  'SEC-025': categories.A06, // Librairie JavaScript obsolète
  'SEC-026': categories.A07  // Limitation de débit non annoncée sur la connexion (CWE-307)
};

// Retourne { code, name } ou null si la règle n'est pas classée.
function getOwaspCategory(ruleId) {
  var category = owaspByRuleId[ruleId];
  return category ? { code: category.code, name: category.name } : null;
}

module.exports = { getOwaspCategory: getOwaspCategory, owaspByRuleId: owaspByRuleId };
