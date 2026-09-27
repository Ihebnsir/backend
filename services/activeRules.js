var net = require('net');
var ssrfGuard = require('./ssrfGuard');

var activeTimeoutMs = 5000;
var maximumSensitiveFileBytes = 64 * 1024;
var sensitivePaths = ['/.env', '/.git/config', '/.git/HEAD'];
var dangerousMethods = ['PUT', 'DELETE', 'TRACE'];

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

function isLoopback(address) {
  return address === '127.0.0.1' || (net.isIP(address) === 6 && address.toLowerCase() === '::1');
}

function isExplicitLocalTarget(url, resolvedIp) {
  var hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  var isExplicitlyAllowed = hostname === 'localhost' || hostname === '127.0.0.1';
  return isExplicitlyAllowed && isLoopback(resolvedIp);
}

async function fetchStatus(url, method, signal) {
  try {
    var response = await fetch(url, {
      method: method,
      redirect: 'manual',
      signal: signal
    });
    var status = response.status;
    var contentType = (response.headers.get('content-type') || '').toLowerCase();
    var body = '';

    if (method === 'GET' && response.body) {
      var reader = response.body.getReader();
      var chunks = [];
      var bytesRead = 0;

      try {
        while (true) {
          var part = await reader.read();
          if (part.done) break;

          var remainingBytes = maximumSensitiveFileBytes - bytesRead;
          if (part.value.byteLength > remainingBytes) {
            if (remainingBytes > 0) chunks.push(part.value.slice(0, remainingBytes));
            await reader.cancel();
            break;
          }

          chunks.push(part.value);
          bytesRead += part.value.byteLength;
          if (bytesRead === maximumSensitiveFileBytes) {
            await reader.cancel();
            break;
          }
        }

        body = Buffer.concat(chunks.map(function(chunk) { return Buffer.from(chunk); })).toString('utf8');
      } finally {
        reader.releaseLock();
      }
    } else if (response.body) {
      await response.body.cancel().catch(function() {});
    }

    return {
      status: status,
      allow: response.headers.get('allow') || '',
      contentType: contentType,
      body: body
    };
  } catch (error) {
    return null;
  }
}

function contentMatchesSensitivePath(path, contentType, body) {
  var normalizedType = (contentType || '').split(';')[0].trim().toLowerCase();
  var beginning = (body || '').replace(/^\uFEFF/, '').trimStart();

  if (normalizedType === 'text/html' || /^(?:<!doctype\s+html\b|<html\b)/i.test(beginning)) {
    return false;
  }

  if (path === '/.env') return /^[A-Z_]+=/m.test(body || '');
  if (path === '/.git/HEAD') return /^ref: refs\/heads\//.test(beginning);
  if (path === '/.git/config') return (body || '').indexOf('[core]') !== -1 || (body || '').indexOf('[remote') !== -1;
  return false;
}

async function evaluateActive(target) {
  var controller = new AbortController();
  var timedOut = false;
  var timeout;
  var timeoutPromise = new Promise(function(resolve) {
    timeout = setTimeout(function() {
      timedOut = true;
      controller.abort();
      resolve([]);
    }, activeTimeoutMs);
  });

  try {
    var checks = (async function() {
      var resolvedIp = await ssrfGuard.assertSafeTarget(target);
      var targetUrl = new URL(target);

      if (!isExplicitLocalTarget(targetUrl, resolvedIp)) {
        // Ces requêtes supplémentaires peuvent toucher des routes sensibles; elles sont interdites hors environnement de test local.
        console.info('Vérifications actives désactivées: la cible n’est pas localhost ou 127.0.0.1.');
        return [];
      }
      if (timedOut) return [];

      var baseUrl = new URL(targetUrl.href);

      var optionsResultPromise = fetchStatus(baseUrl.href, 'OPTIONS', controller.signal);
      var fileResultPromises = sensitivePaths.map(function(path) {
        var fileUrl = new URL(path, baseUrl);
        return fetchStatus(fileUrl.href, 'GET', controller.signal).then(function(result) {
          return { path: path, result: result };
        });
      });
      var results = await Promise.all([optionsResultPromise].concat(fileResultPromises));
      if (timedOut) return [];

      var findings = [];
      var optionsResult = results[0];
      if (optionsResult && optionsResult.allow) {
        var allowedMethods = optionsResult.allow.split(',').map(function(method) {
          return method.trim().toUpperCase();
        });
        var exposedMethods = dangerousMethods.filter(function(method) {
          return allowedMethods.indexOf(method) !== -1;
        });

        if (exposedMethods.length) {
          findings.push(createFinding(
            'SEC-018',
            'Méthodes HTTP dangereuses annoncées',
            'medium',
            'CWE-650',
            { methods: exposedMethods },
            'L’en-tête Allow annonce des méthodes HTTP qui peuvent modifier ou divulguer des ressources.',
            'Désactiver PUT, DELETE ou TRACE si elles ne sont pas indispensables et protéger toute méthode conservée par une autorisation adaptée.'
          ));
        }
      }

      results.slice(1).forEach(function(entry) {
        if (!entry || !entry.result || entry.result.status !== 200 ||
            !contentMatchesSensitivePath(entry.path, entry.result.contentType, entry.result.body)) return;
        findings.push(createFinding(
          'SEC-019',
          'Fichier sensible accessible publiquement',
          'critical',
          'CWE-538',
          { path: entry.path, status: entry.result.status },
          'Un fichier de configuration ou de métadonnées internes est accessible par une requête HTTP.',
          'Retirer ce fichier de la racine publique et configurer le serveur pour en refuser l’accès.'
        ));
      });

      return findings;
    })();

    return await Promise.race([checks, timeoutPromise]);
  } catch (error) {
    return [];
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

module.exports = { evaluateActive: evaluateActive };
