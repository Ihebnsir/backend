function getHeader(headers, expectedName) {
  var headerName = Object.keys(headers || {}).find(function(name) {
    return name.toLowerCase() === expectedName.toLowerCase();
  });
  if (!headerName || headers[headerName] === null || headers[headerName] === undefined) return '';
  return String(headers[headerName]).trim();
}

function createFinding(ruleId, title, severity, cwe, evidence, description, remediation) {
  return {
    ruleId: ruleId,
    title: title,
    severity: severity,
    confidence: 'high',
    cwe: cwe,
    evidence: evidence,
    description: description,
    remediation: remediation,
    fixed: false
  };
}

function evaluateHeaders(headers, cookiesList, isHttps) {
  var findings = [];
  var csp = getHeader(headers, 'content-security-policy');
  var contentTypeOptions = getHeader(headers, 'x-content-type-options');
  var transportSecurity = getHeader(headers, 'strict-transport-security');
  var frameOptions = getHeader(headers, 'x-frame-options');

  if (!csp) {
    findings.push(createFinding(
      'SEC-001',
      'En-tête Content-Security-Policy absent',
      'high',
      'CWE-693',
      { header: 'Content-Security-Policy', value: null },
      'La réponse ne définit pas de Content Security Policy pour limiter les sources de contenu autorisées.',
      'Définir une politique Content-Security-Policy adaptée aux scripts, styles, images et autres ressources du site.'
    ));
  }

  if (contentTypeOptions.toLowerCase() !== 'nosniff') {
    findings.push(createFinding(
      'SEC-002',
      'En-tête X-Content-Type-Options absent ou incorrect',
      'medium',
      'CWE-693',
      { header: 'X-Content-Type-Options', value: contentTypeOptions || null },
      'La réponse ne force pas le navigateur à respecter le type MIME déclaré.',
      'Ajouter l’en-tête X-Content-Type-Options avec la valeur nosniff.'
    ));
  }

  if (isHttps && !transportSecurity) {
    findings.push(createFinding(
      'SEC-003',
      'En-tête Strict-Transport-Security absent',
      'high',
      'CWE-319',
      { header: 'Strict-Transport-Security', value: null },
      'Le site HTTPS ne demande pas au navigateur de privilégier HTTPS pour les prochaines visites.',
      'Configurer Strict-Transport-Security sur HTTPS avec une durée max-age adaptée; n’activer includeSubDomains qu’après vérification des sous-domaines.'
    ));
  }

  if (['DENY', 'SAMEORIGIN'].indexOf(frameOptions.toUpperCase()) === -1) {
    findings.push(createFinding(
      'SEC-004',
      'En-tête X-Frame-Options absent ou incorrect',
      'medium',
      'CWE-1021',
      { header: 'X-Frame-Options', value: frameOptions || null },
      'La réponse ne limite pas l’intégration de cette page dans un cadre externe, ce qui peut faciliter le clickjacking.',
      'Définir X-Frame-Options à DENY ou SAMEORIGIN, et envisager frame-ancestors dans Content-Security-Policy.'
    ));
  }

  // On conserve uniquement le nom et l’attribut manquant, jamais la valeur du cookie qui peut être un secret de session.
  (Array.isArray(cookiesList) ? cookiesList : []).forEach(function(cookie) {
    if (typeof cookie !== 'string' || !cookie.trim()) return;

    var parts = cookie.split(';');
    var cookieName = parts[0].split('=')[0].trim() || '(nom inconnu)';
    var attributes = parts.slice(1).map(function(attribute) {
      return attribute.trim().split('=')[0].toLowerCase();
    });
    var missingAttributes = [
      {
        name: 'Secure',
        cwe: 'CWE-614',
        remediation: 'Ajouter l’attribut Secure au cookie et ne le transmettre que sur HTTPS.'
      },
      {
        name: 'HttpOnly',
        cwe: 'CWE-1004',
        remediation: 'Ajouter l’attribut HttpOnly pour empêcher l’accès au cookie depuis JavaScript côté navigateur.'
      },
      {
        name: 'SameSite',
        cwe: 'CWE-614',
        remediation: 'Définir SameSite=Lax ou SameSite=Strict selon les besoins de navigation inter-sites.'
      }
    ];

    missingAttributes.forEach(function(attribute) {
      if (attributes.indexOf(attribute.name.toLowerCase()) !== -1) return;

      findings.push(createFinding(
        'SEC-005',
        'Cookie sans attribut ' + attribute.name,
        'medium',
        attribute.cwe,
        { cookie: cookieName, attribute: attribute.name, present: false },
        'Le cookie « ' + cookieName + ' » ne définit pas l’attribut ' + attribute.name + '.',
        attribute.remediation
      ));
    });
  });

  ['server', 'x-powered-by'].forEach(function(headerName) {
    var value = getHeader(headers, headerName);
    if (!value) return;

    var displayName = headerName === 'server' ? 'Server' : 'X-Powered-By';
    findings.push(createFinding(
      'SEC-006',
      'En-tête ' + displayName + ' exposé',
      'info',
      'CWE-200',
      { header: displayName, value: value },
      'La réponse révèle une information sur le serveur ou la technologie utilisée.',
      'Si possible, supprimer ou généraliser cet en-tête dans la configuration du serveur ou du framework.'
    ));
  });

  var referrerPolicy = getHeader(headers, 'referrer-policy');
  if (!referrerPolicy || referrerPolicy.toLowerCase() === 'unsafe-url') {
    findings.push(createFinding(
      'SEC-007',
      'En-tête Referrer-Policy absent ou trop permissif',
      'low',
      'CWE-200',
      { header: 'Referrer-Policy', value: referrerPolicy || null },
      'La politique de référent est absente ou peut transmettre l’URL complète lors d’une navigation.',
      'Définir une politique plus restrictive, par exemple strict-origin-when-cross-origin ou no-referrer.'
    ));
  }

  var permissionsPolicy = getHeader(headers, 'permissions-policy');
  if (!permissionsPolicy) {
    findings.push(createFinding(
      'SEC-008',
      'En-tête Permissions-Policy absent',
      'low',
      'CWE-693',
      { header: 'Permissions-Policy', value: null },
      'La réponse ne restreint pas les fonctionnalités du navigateur accessibles à cette page.',
      'Définir Permissions-Policy pour désactiver les fonctionnalités du navigateur que le site n’utilise pas.'
    ));
  }

  var cacheControl = getHeader(headers, 'cache-control');
  var hasCookies = (Array.isArray(cookiesList) && cookiesList.length > 0) || Boolean(getHeader(headers, 'set-cookie'));
  if (hasCookies && !/\b(?:no-store|private)\b/i.test(cacheControl)) {
    var setCookieCount = Array.isArray(cookiesList) && cookiesList.length
      ? cookiesList.length
      : (getHeader(headers, 'set-cookie') ? 1 : 0);
    findings.push(createFinding(
      'SEC-009',
      'Cache-Control insuffisant pour une réponse avec cookie',
      'medium',
      'CWE-525',
      { header: 'Cache-Control', value: cacheControl || null, setCookieCount: setCookieCount },
      'La réponse définit un cookie sans demander explicitement un stockage privé ou l’absence de mise en cache.',
      'Ajouter Cache-Control: no-store pour les réponses sensibles, ou private si leur mise en cache dans le navigateur est acceptable.'
    ));
  }

  var openerPolicy = getHeader(headers, 'cross-origin-opener-policy');
  if (!openerPolicy) {
    findings.push(createFinding(
      'SEC-010',
      'En-tête Cross-Origin-Opener-Policy absent',
      'low',
      'CWE-693',
      { header: 'Cross-Origin-Opener-Policy', value: null },
      'La réponse ne définit pas d’isolation du contexte de navigation vis-à-vis des autres origines.',
      'Évaluer et configurer Cross-Origin-Opener-Policy, par exemple avec same-origin si le site le permet.'
    ));
  }

  return findings;
}

module.exports = { evaluateHeaders: evaluateHeaders };
