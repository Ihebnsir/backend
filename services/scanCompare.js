// Comparaison des findings de deux scans d'un même target.
//
// Logique de comparaison : deux findings représentent « le même problème » s'ils ont
// la même clé d'identité, construite ainsi : ruleId + les seuls champs d'evidence qui
// désignent QUEL élément est concerné (le cookie, le port, le chemin...), listés dans
// identityFields ci-dessous.
//
// Les autres champs d'evidence sont volontairement ignorés, car ils décrivent l'état
// du problème et non son identité : ils peuvent varier d'un scan à l'autre sans que le
// problème ait été corrigé. Exemples :
//   - SEC-009 setCookieCount, SEC-021 status/contentType/totalFound ;
//   - SEC-012/013 validTo (un nouveau certificat qui expire aussi bientôt reste le même problème) ;
//   - SEC-002/004 value (une valeur incorrecte remplacée par une autre valeur incorrecte) ;
//   - SEC-011 protocol (passer de TLS 1.0 à 1.1 ne corrige pas le problème).
// Le titre n'entre pas non plus dans la clé : une reformulation entre deux versions du
// scanner ne doit pas faire apparaître un faux couple « corrigé » + « nouveau ».
//
// Exemple SEC-005 : un finding par cookie et par attribut manquant. La clé contient donc
// cookie + attribut : « session sans Secure » et « session sans HttpOnly » restent
// distincts, tout comme « session sans Secure » et « prefs sans Secure ».
//
// Les valeurs sont normalisées (trim, minuscules, slash final retiré) pour qu'une
// différence de casse ou de forme ne soit pas prise pour un problème différent.
//
// Une règle absente de identityFields n'a qu'une occurrence par scan (en-têtes, TLS...) :
// sa clé est alors le ruleId seul. À mettre à jour si une nouvelle règle peut produire
// plusieurs findings distincts dans un même scan.
var identityFields = {
  'SEC-005': ['cookie', 'attribute'],
  'SEC-006': ['header'],
  'SEC-014': ['action'],
  'SEC-015': ['action'],
  'SEC-017': ['tag', 'url'],
  'SEC-019': ['path'],
  'SEC-021': ['path'],
  'SEC-023': ['port'],
  'SEC-024': ['cname'],
  'SEC-025': ['library'],
  'SEC-026': ['route']
};

function normalize(value) {
  if (value === undefined || value === null) return '';
  var text = String(value).trim().toLowerCase();
  return text.length > 1 ? text.replace(/\/+$/, '') : text;
}

function identityKey(finding) {
  var evidence = finding.evidence && typeof finding.evidence === 'object' ? finding.evidence : {};
  var fields = identityFields[finding.ruleId] || [];

  return [finding.ruleId].concat(fields.map(function(field) {
    return field + '=' + normalize(evidence[field]);
  })).join('|');
}

function summarize(finding) {
  return {
    findingId: finding._id,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    evidence: finding.evidence
  };
}

function groupByKey(findings) {
  var groups = new Map();
  findings.forEach(function(finding) {
    var key = identityKey(finding);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  });
  return groups;
}

// Une même clé peut apparaître plusieurs fois dans un scan (par exemple deux ressources
// mixtes identiques). On apparie donc les occurrences une à une : les paires communes
// sont « persistantes », le surplus de l'ancien scan est « corrigé », celui du nouveau est « nouveau ».
// Le champ fixed (marquage manuel) n'est pas pris en compte : seule la présence dans le scan compte.
function compareFindings(previousFindings, currentFindings) {
  var previousGroups = groupByKey(previousFindings || []);
  var currentGroups = groupByKey(currentFindings || []);
  var result = { fixed: [], new: [], persisting: [] };

  currentGroups.forEach(function(current, key) {
    var previous = previousGroups.get(key) || [];
    current.forEach(function(finding, index) {
      // Pour un finding persistant, on renvoie la version du scan actuel.
      (index < previous.length ? result.persisting : result.new).push(summarize(finding));
    });
  });

  previousGroups.forEach(function(previous, key) {
    var currentCount = (currentGroups.get(key) || []).length;
    previous.slice(currentCount).forEach(function(finding) {
      result.fixed.push(summarize(finding));
    });
  });

  return result;
}

module.exports = { compareFindings, identityKey };
