var httpProbe = require('./httpProbe');
var securityRules = require('./securityRules');
var tlsRules = require('./tlsRules');
var htmlRules = require('./htmlRules');
var activeRules = require('./activeRules');

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
    }).catch(function() { return []; })
  ]);

  additionalFindings.forEach(function(groupFindings) {
    if (Array.isArray(groupFindings)) findings = findings.concat(groupFindings);
  });

  if (probeResult.redirectNotFollowed) {
    findings.push(createRedirectFinding(probeResult));
  }

  return {
    status: probeResult.status,
    findings: findings,
    isHttps: probeResult.isHttps
  };
}

module.exports = { runScan: runScan };
