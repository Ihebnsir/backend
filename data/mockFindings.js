module.exports = [
  {
    ruleId: 'SEC-001',
    title: 'En-têtes de sécurité incomplets',
    severity: 'high',
    confidence: 'high',
    cwe: 'CWE-693',
    evidence: { header: 'Content-Security-Policy' },
    description: 'Un en-tête de sécurité important est absent.',
    remediation: 'Configurer les en-têtes de sécurité côté serveur.'
  },
  {
    ruleId: 'SEC-002',
    title: 'Cookie sans attribut Secure',
    severity: 'medium',
    confidence: 'medium',
    cwe: 'CWE-614',
    evidence: { cookie: 'session' },
    description: 'Un cookie de session fictif n impose pas HTTPS.',
    remediation: 'Ajouter l attribut Secure au cookie.'
  },
  {
    ruleId: 'SEC-003',
    title: 'Formulaire sans protection CSRF',
    severity: 'high',
    confidence: 'low',
    cwe: 'CWE-352',
    evidence: { form: '/account' },
    description: 'Un formulaire fictif ne contient pas de jeton CSRF.',
    remediation: 'Ajouter une protection CSRF aux formulaires sensibles.'
  },
  {
    ruleId: 'SEC-004',
    title: 'Informations de version exposées',
    severity: 'low',
    confidence: 'high',
    cwe: 'CWE-200',
    evidence: { header: 'Server' },
    description: 'La version d un serveur fictif est visible.',
    remediation: 'Masquer les informations de version.'
  },
  {
    ruleId: 'SEC-005',
    title: 'Observation informative',
    severity: 'info',
    confidence: 'high',
    cwe: 'CWE-0',
    evidence: { note: 'Donnée fictive' },
    description: 'Résultat informatif sans impact direct.',
    remediation: 'Aucune action urgente nécessaire.'
  }
];
