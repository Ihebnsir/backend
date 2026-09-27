var cheerio = require('cheerio');

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

function evaluateHtml(body, isHttps) {
  try {
    var $ = cheerio.load(typeof body === 'string' ? body : '');
    var findings = [];

    $('form').each(function() {
      var form = $(this);
      var method = (form.attr('method') || 'get').trim().toLowerCase();
      var action = form.attr('action') || '';

      if (method === 'post') {
        var hasTokenField = form.find('input').toArray().some(function(input) {
          var inputElement = $(input);
          var name = (inputElement.attr('name') || '').toLowerCase();
          var type = (inputElement.attr('type') || 'text').toLowerCase();
          return type === 'hidden' && (name.indexOf('csrf') !== -1 || name.indexOf('token') !== -1);
        });

        if (!hasTokenField) {
          findings.push(createFinding(
            'SEC-014',
            'Formulaire POST sans champ de protection CSRF visible',
            'medium',
            'CWE-352',
            { action: action },
            'Le formulaire POST ne contient pas de champ caché dont le nom indique un jeton CSRF.',
            'Protéger cette opération côté serveur avec un jeton CSRF imprévisible et vérifié à la soumission.'
          ));
        }
      }

      if (isHttps && /^http:\/\//i.test(action)) {
        findings.push(createFinding(
          'SEC-015',
          'Formulaire HTTPS envoyé vers une action HTTP',
          'high',
          'CWE-319',
          { action: action },
          'Le formulaire transmet ses données vers HTTP depuis une page HTTPS, ce qui peut exposer ces données en transit.',
          'Remplacer l’action par une destination HTTPS et vérifier que cette destination applique TLS.'
        ));
      }
    });

    var unprotectedBlankLinks = [];
    $('a[target]').each(function() {
      var link = $(this);
      if ((link.attr('target') || '').toLowerCase() !== '_blank') return;

      var relValues = (link.attr('rel') || '').toLowerCase().split(/\s+/);
      if (relValues.indexOf('noopener') === -1) {
        unprotectedBlankLinks.push(link.attr('href') || '');
      }
    });

    unprotectedBlankLinks.slice(0, 5).forEach(function(href) {
      findings.push(createFinding(
        'SEC-016',
        'Lien target="_blank" sans rel="noopener"',
        'low',
        'CWE-1022',
        { href: href, totalFound: unprotectedBlankLinks.length },
        'Un lien ouvert dans un nouvel onglet ne définit pas rel="noopener".',
        'Ajouter noopener à l’attribut rel de ce lien; ajouter noreferrer si la suppression du référent est également souhaitée.'
      ));
    });

    if (isHttps) {
      $('script[src], img[src], link[href]').each(function() {
        var element = $(this);
        var tagName = this.tagName.toLowerCase();
        var attributeName = tagName === 'link' ? 'href' : 'src';
        var resourceUrl = element.attr(attributeName) || '';
        if (!/^http:\/\//i.test(resourceUrl)) return;

        findings.push(createFinding(
          'SEC-017',
          'Ressource HTTP chargée depuis une page HTTPS',
          'medium',
          'CWE-319',
          { tag: tagName, url: resourceUrl },
          'La page HTTPS charge une ressource en HTTP, ce qui crée du contenu mixte et peut permettre sa modification en transit.',
          'Servir cette ressource en HTTPS ou la retirer si sa version sécurisée n’est pas disponible.'
        ));
      });
    }

    findings.sort(function(first, second) {
      return Number(first.ruleId.slice(4)) - Number(second.ruleId.slice(4));
    });
    return findings;
  } catch (error) {
    console.warn('Analyse HTML ignorée après une erreur du parseur.');
    return [];
  }
}

module.exports = { evaluateHtml: evaluateHtml };
