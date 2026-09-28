var dns = require('dns').promises;
var net = require('net');
var ssrfGuard = require('./ssrfGuard');

var dnsTimeoutMs = 5000;
var maximumBodyBytes = 64 * 1024;

// Liste courte et pédagogique (pas exhaustive) de services où un sous-domaine orphelin
// peut être récupéré. Chaque empreinte est le message affiché par le service quand la
// ressource visée n'existe plus :
// - GitHub Pages : page 404 "There isn't a GitHub Pages site here."
// - Heroku : page d'erreur "No such app" (application supprimée ou jamais créée)
// - AWS S3 : erreur XML "NoSuchBucket" / "The specified bucket does not exist"
// - Vercel : code d'erreur "DEPLOYMENT_NOT_FOUND" (déploiement introuvable)
// - Netlify : page "Not Found - Request ID" (aucun site associé à ce nom)
var takeoverServices = [
  {
    service: 'GitHub Pages',
    matches: function(cname) { return cname.endsWith('.github.io'); },
    fingerprints: ["There isn't a GitHub Pages site here"]
  },
  {
    service: 'Heroku',
    matches: function(cname) { return cname.endsWith('.herokuapp.com'); },
    fingerprints: ['No such app']
  },
  {
    service: 'AWS S3',
    // "s3-website" n'est accepté que sous amazonaws.com : un nom arbitraire contenant
    // "s3-website" ne doit pas suffire à déclencher une requête.
    matches: function(cname) {
      return cname.endsWith('.s3.amazonaws.com') ||
        (cname.indexOf('.s3-website') !== -1 && cname.endsWith('.amazonaws.com'));
    },
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist']
  },
  {
    service: 'Vercel',
    matches: function(cname) { return cname.endsWith('.vercel.app'); },
    fingerprints: ['DEPLOYMENT_NOT_FOUND']
  },
  {
    service: 'Netlify',
    matches: function(cname) { return cname.endsWith('.netlify.app'); },
    fingerprints: ['Not Found - Request ID']
  }
];

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

function normalizeHostname(hostname) {
  return hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

async function readLimitedBody(response) {
  if (!response.body) return '';

  var reader = response.body.getReader();
  var chunks = [];
  var bytesRead = 0;

  try {
    while (bytesRead < maximumBodyBytes) {
      var part = await reader.read();
      if (part.done) break;
      chunks.push(Buffer.from(part.value));
      bytesRead += part.value.byteLength;
    }
    if (bytesRead >= maximumBodyBytes) await reader.cancel();
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks).toString('utf8').slice(0, maximumBodyBytes);
}

// SEC-024 : règle PASSIVE, exécutée sur toutes les cibles. Elle ne fait qu'une lecture DNS
// (le CNAME de la cible) puis une requête GET ordinaire vers le service tiers désigné par
// ce CNAME : la cible elle-même ne reçoit aucune requête supplémentaire, d'où l'absence
// du garde-fou localhost réservé aux vérifications actives (SEC-018 à SEC-023).
// La protection SSRF reste obligatoire : le CNAME est choisi par le propriétaire du domaine
// scanné, donc potentiellement par un attaquant, et le serveur de SecuLens ne doit jamais
// être amené à interroger une adresse privée de son propre réseau.
async function evaluateDns(target) {
  var controller = new AbortController();
  var timeout;
  var timeoutPromise = new Promise(function(resolve) {
    timeout = setTimeout(function() {
      controller.abort();
      resolve([]);
    }, dnsTimeoutMs);
  });

  try {
    var check = (async function() {
      var hostname = normalizeHostname(new URL(target).hostname);
      if (net.isIP(hostname)) return [];

      // Seul appel DNS de la règle : absence de CNAME (ENODATA, ENOTFOUND...) = rien à signaler.
      var cnames = await dns.resolveCname(hostname).catch(function() { return []; });
      if (!cnames.length) return [];

      var cname = normalizeHostname(cnames[0]);
      if (cname === hostname) return [];

      var provider = takeoverServices.find(function(entry) { return entry.matches(cname); });
      if (!provider) return [];

      // Les points de terminaison "s3-website" ne servent que du HTTP.
      var probeUrl = (cname.indexOf('.s3-website') !== -1 ? 'http://' : 'https://') + cname + '/';
      await ssrfGuard.assertSafeTarget(probeUrl);

      // Seul appel HTTP de la règle, sans suivre de redirection.
      var response = await fetch(probeUrl, { redirect: 'manual', signal: controller.signal });
      var body = await readLimitedBody(response);

      var orphaned = provider.fingerprints.some(function(fingerprint) {
        return body.indexOf(fingerprint) !== -1;
      });
      // Service connu mais sans message d'erreur caractéristique : probablement sain, aucun finding.
      if (!orphaned) return [];

      return [createFinding(
        'SEC-024',
        'Sous-domaine exposé à une prise de contrôle',
        'critical',
        'CWE-350',
        { cname: cname, service: provider.service },
        'Le nom de domaine pointe (CNAME) vers ' + provider.service + ', mais la ressource correspondante n’existe plus. ' +
          'Un attaquant pourrait la recréer à son nom et servir son propre contenu sur ce sous-domaine.',
        'Supprimer l’enregistrement CNAME s’il n’est plus utilisé, ou recréer immédiatement la ressource sur ' +
          provider.service + ' pour en reprendre le contrôle.'
      )];
    })();

    return await Promise.race([check, timeoutPromise]);
  } catch (error) {
    // Refus SSRF, erreur réseau ou délai dépassé : la règle est ignorée sans faire échouer le scan.
    return [];
  } finally {
    clearTimeout(timeout);
    controller.abort();
  }
}

module.exports = { evaluateDns: evaluateDns };
