var net = require('net');
var ssrfGuard = require('./ssrfGuard');

var activeTimeoutMs = 5000;
var maximumSensitiveFileBytes = 64 * 1024;
var sensitivePaths = ['/.env', '/.git/config', '/.git/HEAD'];
var dangerousMethods = ['PUT', 'DELETE', 'TRACE'];
// Liste fixe des endpoints testés par SEC-021 : aucun autre chemin n'est essayé.
var exposedApiPaths = [
  '/api/', '/api/v1/', '/api/docs', '/swagger.json', '/swagger/index.html',
  '/graphql', '/admin', '/api/admin'
];
// Chemins dont le contenu légitime peut être une page HTML (docs ou administration).
var htmlApiPaths = ['/api/docs', '/swagger/index.html', '/admin'];
var maximumApiFindings = 3;
// SEC-023 : liste fixe et fermée des ports testés, aucun autre port n'est jamais essayé.
// Les bases de données sont en "high" : un accès direct aux données est plus grave qu'un SSH standard.
var sensitivePorts = [
  { port: 21, commonService: 'FTP', severity: 'medium' },
  { port: 22, commonService: 'SSH', severity: 'medium' },
  { port: 23, commonService: 'Telnet', severity: 'medium' },
  { port: 3306, commonService: 'MySQL', severity: 'high' },
  { port: 5432, commonService: 'PostgreSQL', severity: 'high' },
  { port: 6379, commonService: 'Redis', severity: 'high' },
  { port: 27017, commonService: 'MongoDB', severity: 'high' },
  { port: 9200, commonService: 'Elasticsearch', severity: 'medium' }
];
var portTimeoutMs = 500;
var maximumPortFindings = 5;

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

function isHtmlResponse(contentType, body) {
  var normalizedType = (contentType || '').split(';')[0].trim().toLowerCase();
  var beginning = (body || '').replace(/^\uFEFF/, '').trimStart();
  return normalizedType === 'text/html' || /^(?:<!doctype\s+html\b|<html\b)/i.test(beginning);
}

function isValidJson(body) {
  try {
    JSON.parse(body);
    return true;
  } catch (error) {
    return false;
  }
}

// Une réponse HTML identique à la page racine est le fallback d'une SPA, pas une vraie page.
function differsFromFallback(body, fallbackBody) {
  return fallbackBody !== null && (body || '').trim() !== fallbackBody.trim();
}

// Même garde-fou anti-faux-positif que SEC-019 : une réponse HTML n'est retenue que pour
// les pages de docs/admin et seulement si elle diffère du fallback de la SPA (page racine).
function contentMatchesApiPath(path, result, fallbackBody) {
  var body = result.body || '';
  if (!body.trim()) return false;

  if (isHtmlResponse(result.contentType, body)) {
    if (htmlApiPaths.indexOf(path) === -1) return false;
    return differsFromFallback(body, fallbackBody);
  }

  return isValidJson(body);
}

// Extrait la version depuis <meta name="generator" content="WordPress X.Y[.Z]">,
// seule source jugée fiable pour la version (l'ordre des attributs peut varier).
function extractWordPressVersion(html) {
  var metaTags = (html || '').match(/<meta\b[^>]*>/gi) || [];
  for (var i = 0; i < metaTags.length; i++) {
    if (!/\bname\s*=\s*["']?generator\b/i.test(metaTags[i])) continue;
    var match = metaTags[i].match(/\bcontent\s*=\s*["']?\s*WordPress\s+(\d+(?:\.\d+){0,2})/i);
    if (match) return match[1];
  }
  return null;
}

// Détection séquentielle de WordPress : chaque indice n'est testé que si le précédent a échoué,
// avec au plus une requête par étape. La page racine (étape b) est déjà téléchargée comme
// référence du fallback SPA, elle ne coûte donc aucune requête supplémentaire.
async function detectWordPress(baseUrl, fallbackResultPromise, signal) {
  var loginResult = await fetchStatus(new URL('/wp-login.php', baseUrl).href, 'GET', signal);
  var fallbackResult = await fallbackResultPromise;
  var rootBody = fallbackResult && fallbackResult.status === 200 ? fallbackResult.body : null;
  // La version vient toujours de la meta generator de la page racine, quel que soit l'indice.
  var version = extractWordPressVersion(rootBody);

  if (loginResult && loginResult.status === 200 &&
      /wp-submit|user_login/.test(loginResult.body || '')) {
    return { method: 'wp-login', version: version };
  }
  if (version) return { method: 'meta-generator', version: version };

  var contentResult = await fetchStatus(new URL('/wp-content/', baseUrl).href, 'GET', signal);
  if (contentResult && contentResult.status === 200 &&
      (!isHtmlResponse(contentResult.contentType, contentResult.body) ||
        differsFromFallback(contentResult.body, rootBody))) {
    return { method: 'wp-content', version: null };
  }
  return null;
}

// Liste pédagogique simplifiée, PAS une vraie base de vulnérabilités : seuils statiques
// (< 6.0 obsolète, 6.0–6.2 datée) choisis pour illustrer le principe. Retourne null si récente.
function classifyWordPressVersion(version) {
  var parts = version.split('.').map(Number);
  var major = parts[0];
  var minor = parts[1] || 0;
  if (major < 6) {
    return { severity: 'high', message: 'version majeure obsolète, mises à jour de sécurité manquantes' };
  }
  if (major === 6 && minor < 3) {
    return { severity: 'medium', message: 'version datée, vérifier les mises à jour disponibles' };
  }
  return null;
}

function createWordPressFinding(detection) {
  var evidence = { method: detection.method };
  if (detection.version) evidence.version = detection.version;

  var outdated = detection.version ? classifyWordPressVersion(detection.version) : null;
  if (outdated) {
    return createFinding(
      'SEC-022',
      'Version de WordPress obsolète',
      outdated.severity,
      'CWE-1104',
      evidence,
      'WordPress ' + detection.version + ' détecté : ' + outdated.message + '.',
      'Mettre à jour WordPress vers la dernière version stable, ainsi que les thèmes et extensions.'
    );
  }

  return createFinding(
    'SEC-022',
    'WordPress détecté',
    'info',
    'CWE-200',
    evidence,
    detection.version
      ? 'WordPress ' + detection.version + ' détecté.'
      : 'WordPress détecté, version non déterminée.',
    'Garder WordPress à jour et envisager de masquer la balise meta generator qui révèle la version.'
  );
}

function contentMatchesSensitivePath(path, contentType, body) {
  var beginning = (body || '').replace(/^\uFEFF/, '').trimStart();

  if (isHtmlResponse(contentType, body)) {
    return false;
  }

  if (path === '/.env') return /^[A-Z_]+=/m.test(body || '');
  if (path === '/.git/HEAD') return /^ref: refs\/heads\//.test(beginning);
  if (path === '/.git/config') return (body || '').indexOf('[core]') !== -1 || (body || '').indexOf('[remote') !== -1;
  return false;
}

// Tente une simple connexion TCP : on ne lit rien et on n'envoie rien (pas de bannière,
// pas d'identification du service), la socket est fermée dès que la connexion aboutit.
// Échec, refus ou délai dépassé signifient seulement "fermé ou filtré" : jamais d'erreur remontée.
function isPortOpen(host, port) {
  return new Promise(function(resolve) {
    var socket = new net.Socket();
    var settled = false;

    function finish(open) {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    }

    socket.setTimeout(portTimeoutMs);
    socket.once('connect', function() { finish(true); });
    socket.once('timeout', function() { finish(false); });
    socket.once('error', function() { finish(false); });
    socket.connect(port, host);
  });
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
      // La page racine sert de référence pour reconnaître le fallback HTML d'une SPA.
      var fallbackResultPromise = fetchStatus(baseUrl.href, 'GET', controller.signal);
      var apiResultPromises = exposedApiPaths.map(function(path) {
        var apiUrl = new URL(path, baseUrl);
        return fetchStatus(apiUrl.href, 'GET', controller.signal).then(function(result) {
          return { path: path, result: result };
        });
      });
      var wordPressPromise = detectWordPress(baseUrl, fallbackResultPromise, controller.signal);
      // SEC-023 est la vérification la plus intrusive : sonder des ports hors HTTP ressemble à un scan
      // de ports, ce qui sur une machine tierce serait une intrusion. Elle n'existe donc que derrière le
      // garde-fou localhost ci-dessus, sans exception ni paramètre pour l'élargir. On se connecte à l'IP
      // de boucle locale déjà validée (resolvedIp), jamais à un nom qui pourrait être résolu à nouveau.
      var portResultsPromise = Promise.all(sensitivePorts.map(function(entry) {
        return isPortOpen(resolvedIp, entry.port).then(function(open) {
          return { entry: entry, open: open };
        });
      }));
      var results = await Promise.all([optionsResultPromise].concat(fileResultPromises));
      var fallbackResult = await fallbackResultPromise;
      var apiResults = await Promise.all(apiResultPromises);
      var wordPress = await wordPressPromise;
      var portResults = await portResultsPromise;
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

      var fallbackBody = fallbackResult ? fallbackResult.body : null;
      var exposedApis = apiResults.filter(function(entry) {
        return entry.result && entry.result.status === 200 &&
          contentMatchesApiPath(entry.path, entry.result, fallbackBody);
      });

      // Au plus 3 findings pour ne pas noyer les résultats ; le total figure dans le premier.
      exposedApis.slice(0, maximumApiFindings).forEach(function(entry, index) {
        var evidence = {
          path: entry.path,
          status: entry.result.status,
          contentType: (entry.result.contentType.split(';')[0].trim() || 'inconnu').slice(0, 60)
        };
        if (index === 0) evidence.totalFound = exposedApis.length;

        findings.push(createFinding(
          'SEC-021',
          'Endpoint API ou d’administration exposé',
          'medium',
          'CWE-284',
          evidence,
          'Un endpoint API, de documentation ou d’administration répond publiquement avec un contenu réel.',
          'Vérifier que cet endpoint doit être public ; sinon le retirer ou le protéger par une authentification et un contrôle d’accès.'
        ));
      });

      if (wordPress) findings.push(createWordPressFinding(wordPress));

      // Le finding constate seulement que le port répond : le service réel n'est ni identifié ni confirmé.
      portResults.filter(function(result) { return result.open; })
        .slice(0, maximumPortFindings)
        .forEach(function(result) {
          findings.push(createFinding(
            'SEC-023',
            'Port TCP sensible ouvert',
            result.entry.severity,
            'CWE-200',
            { port: result.entry.port, commonService: result.entry.commonService },
            'Le port ' + result.entry.port + ' accepte les connexions TCP. Il est habituellement utilisé par ' +
              result.entry.commonService + ', mais le service réellement présent n’a pas été vérifié.',
            'Fermer ce port s’il n’est pas nécessaire, ou restreindre son accès par pare-feu aux seules machines autorisées.'
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
