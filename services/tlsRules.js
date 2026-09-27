var tls = require('tls');
var net = require('net');
var ssrfGuard = require('./ssrfGuard');

var tlsTimeoutMs = 3000;
var dayInMilliseconds = 24 * 60 * 60 * 1000;

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

function evaluateCertificate(certificate, protocol) {
  var findings = [];

  if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
    findings.push(createFinding(
      'SEC-011',
      'Version TLS obsolète',
      'high',
      'CWE-326',
      { protocol: protocol },
      'La connexion HTTPS a négocié une version ancienne de TLS qui ne fournit plus un niveau de sécurité recommandé.',
      'Désactiver TLS 1.0 et TLS 1.1 côté serveur et conserver TLS 1.2 ou TLS 1.3.'
    ));
  }

  var validTo = certificate && certificate.valid_to;
  var expirationTime = validTo ? Date.parse(validTo) : NaN;
  if (!Number.isFinite(expirationTime)) return findings;

  var now = Date.now();
  var evidence = { validTo: new Date(expirationTime).toISOString() };
  if (expirationTime <= now) {
    findings.push(createFinding(
      'SEC-013',
      'Certificat TLS expiré',
      'critical',
      'CWE-298',
      evidence,
      'Le certificat présenté par le serveur a dépassé sa date de validité.',
      'Renouveler et installer un certificat TLS valide dès que possible.'
    ));
  } else if (expirationTime - now < 30 * dayInMilliseconds) {
    findings.push(createFinding(
      'SEC-012',
      'Certificat TLS bientôt expiré',
      'medium',
      'CWE-298',
      evidence,
      'Le certificat TLS arrivera à expiration dans moins de 30 jours.',
      'Renouveler le certificat avant sa date d’expiration et vérifier son renouvellement automatique.'
    ));
  }

  return findings;
}

function connectAndInspect(options, onSocket) {
  return new Promise(function(resolve, reject) {
    var socket;
    var settled = false;

    function finish(error, findings) {
      if (settled) return;
      settled = true;
      if (socket) socket.destroy();
      if (error) reject(error);
      else resolve(findings);
    }

    try {
      socket = tls.connect(options, function() {
        try {
          var certificate = socket.getPeerCertificate();
          var protocol = socket.getProtocol();
          finish(null, evaluateCertificate(certificate, protocol));
        } catch (error) {
          finish(error);
        }
      });
      onSocket(socket);
      socket.once('error', function(error) { finish(error); });
    } catch (error) {
      finish(error);
    }
  });
}

async function evaluateTls(target, isHttps) {
  if (!isHttps) return [];

  var socket;
  var timedOut = false;
  var timeout;
  var timeoutPromise = new Promise(function(resolve) {
    timeout = setTimeout(function() {
      timedOut = true;
      if (socket) socket.destroy();
      console.warn('Vérification TLS ignorée après un délai de 3 secondes.');
      resolve([]);
    }, tlsTimeoutMs);
  });

  try {
    var inspection = (async function() {
      var resolvedIp = await ssrfGuard.assertSafeTarget(target);
      if (timedOut) return [];

      var parsedUrl = new URL(target);
      var hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '');
      var port = parsedUrl.port ? Number(parsedUrl.port) : 443;
      var options = {
        host: resolvedIp,
        port: port,
        rejectUnauthorized: false,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.3'
      };

      if (!net.isIP(hostname)) options.servername = hostname;

      return connectAndInspect(options, function(connection) { socket = connection; });
    })();

    return await Promise.race([inspection, timeoutPromise]);
  } catch (error) {
    console.warn('Vérification TLS ignorée après une erreur:', error.message);
    return [];
  } finally {
    clearTimeout(timeout);
    if (socket) socket.destroy();
  }
}

module.exports = { evaluateTls: evaluateTls };
