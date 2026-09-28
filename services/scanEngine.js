// Version des règles du scanner, enregistrée sur chaque scan.
// À INCRÉMENTER À LA MAIN à chaque ajout, suppression ou modification d'une règle :
// deux scores ne sont comparables que s'ils ont été produits par la même version.
// Historique : 1.0 = 20 règles (SEC-001 à SEC-020). Les scans plus anciens n'ont pas de version.
var SCANNER_VERSION = '1.4';

var httpProbe = require('./httpProbe');
var securityRules = require('./securityRules');
var tlsRules = require('./tlsRules');
var htmlRules = require('./htmlRules');
var activeRules = require('./activeRules');
var dnsRules = require('./dnsRules');

function createRedirectFinding(probeResult) {
  var destinationWasBlocked = Boolean(probeResult.redirectBlocked);

  return {
    ruleId: 'HTTP-REDIRECT',
    title: 'Redirection HTTP non suivie',
    severity: 'info',
    confidence: 'high',
    cwe: 'CWE-0',
    evidence: {
      status: probeResult.status,
      destination: destinationWasBlocked ? 'bloquée par la validation SSRF' : 'non suivie'
    },
    description: destinationWasBlocked
      ? 'La cible a redirigé vers une adresse non autorisée; le moteur a bloqué cette destination.'
      : 'La cible a demandé une redirection supplémentaire que le moteur n’a pas suivie.',
    remediation: 'Vérifier que la redirection est attendue et lancer un scan séparé sur une cible publique autorisée.',
    fixed: false
  };
}

// Page plus grande que la limite de lecture (2 Mo) : les règles HTML n'ont vu que le début.
// Sévérité "info" : le score n'est pas affecté, mais l'utilisateur sait que l'analyse HTML est partielle.
function createTruncatedBodyFinding() {
  return {
    ruleId: 'SEC-020',
    title: 'Page HTML tronquée pendant l’analyse',
    severity: 'info',
    confidence: 'high',
    cwe: 'CWE-0',
    evidence: { analyzedBytes: httpProbe.maximumHtmlBytes, limit: '2 Mo' },
    description: 'La page dépasse la taille maximale lue par le scanner ; seuls les 2 premiers Mo du HTML ont été analysés. Des formulaires, liens ou ressources situés après cette limite n’ont pas été vérifiés.',
    remediation: 'Vérifier manuellement la fin de la page, ou réduire la taille du HTML (pagination, chargement différé des contenus volumineux).',
    fixed: false
  };
}

async function runScan(target) {
  var probeResult;

  try {
    probeResult = await httpProbe.probe(target);
  } catch (error) {
    return {
      status: null,
      findings: [],
      isHttps: false,
      error: {
        code: error && error.code ? error.code : 'SCAN_PROBE_ERROR',
        message: error && error.message ? error.message : 'La sonde de la cible a échoué.'
      }
    };
  }

  if (probeResult.error) {
    return {
      status: null,
      findings: [],
      isHttps: probeResult.isHttps,
      error: probeResult.error
    };
  }

  var findings = securityRules.evaluateHeaders(
    probeResult.headers,
    probeResult.cookies,
    probeResult.isHttps
  );

  var additionalFindings = await Promise.all([
    Promise.resolve().then(function() {
      return probeResult.isHttps ? tlsRules.evaluateTls(target, true) : [];
    }).catch(function() { return []; }),
    Promise.resolve().then(function() {
      return htmlRules.evaluateHtml(probeResult.body, probeResult.isHttps);
    }).catch(function() { return []; }),
    Promise.resolve().then(function() {
      return activeRules.evaluateActive(target);
    }).catch(function() { return []; }),
    Promise.resolve().then(function() {
      return dnsRules.evaluateDns(target);
    }).catch(function() { return []; })
  ]);

  additionalFindings.forEach(function(groupFindings) {
    if (Array.isArray(groupFindings)) findings = findings.concat(groupFindings);
  });

  if (probeResult.redirectNotFollowed) {
    findings.push(createRedirectFinding(probeResult));
  }

  if (probeResult.bodyTruncated) {
    findings.push(createTruncatedBodyFinding());
  }

  return {
    status: probeResult.status,
    findings: findings,
    isHttps: probeResult.isHttps
  };
}

module.exports = { runScan: runScan, SCANNER_VERSION: SCANNER_VERSION };
