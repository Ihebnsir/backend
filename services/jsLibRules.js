var cheerio = require('cheerio');

// SEC-025 : librairies JavaScript obsolètes chargées via <script src="...">.
// Règle PASSIVE : elle relit le HTML déjà téléchargé par httpProbe, aucune requête n'est envoyée.
//
// ATTENTION, extraction volontairement APPROXIMATIVE (choix pédagogique assumé) :
// la librairie et sa version sont devinées uniquement à partir de l'URL du script
// (nom du fichier, paramètre ?v=, dossier de CDN). Cela rate :
//   - les CDN ou bundles qui ne mettent pas la version dans l'URL (ex. /js/vendor.js) ;
//   - les builds personnalisés ou renommés, les scripts inline, les librairies chargées dynamiquement ;
//   - une URL qui ment (fichier renommé sans mettre à jour son contenu).
// Un vrai outil (Retire.js, Snyk…) lit le contenu du fichier et le compare à une base de CVE.
// Ici la liste de seuils est statique et courte, comme pour WordPress (SEC-022).

var maximumFindings = 5;
var maximumSrcLength = 200;

// Le nom de fichier doit correspondre EXACTEMENT à la librairie principale, pour ne pas
// confondre jQuery avec ses plugins (jquery-ui.js, jquery.validate.js…).
// AngularJS 1.x est distribué sous le nom angular(.min).js ; Angular 2+ ne l'est pas.
// folders : noms de dossier utilisés par les CDN (/ajax/libs/angularjs/1.5.8/, npm/angular@1.5.8…).
var libraries = [
  { id: 'jquery', name: 'jQuery', folders: 'jquery', filePattern: /^jquery(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.slim)?(?:\.min)?\.js$/ },
  { id: 'bootstrap', name: 'Bootstrap', folders: 'bootstrap', filePattern: /^bootstrap(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.bundle)?(?:\.min)?\.js$/ },
  { id: 'angularjs', name: 'AngularJS', folders: 'angular|angularjs|angular\\.js', filePattern: /^angular(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js$/ }
];

function createFinding(ruleId, title, severity, confidence, cwe, evidence, description, remediation) {
  return {
    ruleId: ruleId,
    title: title,
    severity: severity,
    confidence: confidence,
    cwe: cwe,
    evidence: evidence,
    description: description,
    remediation: remediation,
    fixed: false
  };
}

// Compare deux versions "1.6.4" / "3.4" segment par segment (segment absent = 0).
function compareVersions(first, second) {
  var a = first.split('.').map(Number);
  var b = second.split('.').map(Number);
  for (var index = 0; index < Math.max(a.length, b.length); index++) {
    var difference = (a[index] || 0) - (b[index] || 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

// Cherche la version, dans l'ordre : nom du fichier (jquery-3.6.0.min.js),
// paramètre de requête (?v=1.6.4), puis dossier de CDN (/jquery/1.6.4/ ou jquery@1.6.4).
function extractVersion(library, fileVersion, path, query) {
  if (fileVersion) return fileVersion;

  var queryMatch = /(?:^|&)(?:v|ver|version)=v?(\d+\.\d+(?:\.\d+)?)/.exec(query);
  if (queryMatch) return queryMatch[1];

  var pathMatch = new RegExp('/(?:' + library.folders + ')(?:/|@)v?(\\d+\\.\\d+(?:\\.\\d+)?)(?:/|$)').exec(path);
  return pathMatch ? pathMatch[1] : null;
}

function detectLibrary(src) {
  var lowerSrc = src.trim().toLowerCase();
  var path = lowerSrc.split(/[?#]/)[0];
  var query = (lowerSrc.split('#')[0].split('?')[1]) || '';
  var fileName = path.slice(path.lastIndexOf('/') + 1);

  for (var index = 0; index < libraries.length; index++) {
    var library = libraries[index];
    var match = library.filePattern.exec(fileName);
    if (match) {
      return { library: library, version: extractVersion(library, match[1], path, query) };
    }
  }
  return null;
}

// Liste statique de seuils (même principe que classifyWordPressVersion pour SEC-022).
function classifyLibrary(libraryId, version) {
  if (libraryId === 'angularjs') {
    // Toutes les versions 1.x sont concernées : la version détectée ne change rien.
    return {
      severity: 'high',
      message: 'AngularJS 1.x est en fin de vie (EOL) depuis janvier 2022, ne reçoit plus aucun correctif de sécurité, migration recommandée'
    };
  }
  if (!version) return null;

  if (libraryId === 'jquery') {
    if (compareVersions(version, '1.9') < 0) {
      return { severity: 'high', message: 'version très ancienne, nombreuses failles XSS documentées avant la 1.9' };
    }
    if (compareVersions(version, '3.4.0') < 0) {
      return { severity: 'medium', message: 'version antérieure à la 3.4.0, failles XSS et de pollution de prototype connues' };
    }
    return null;
  }

  if (libraryId === 'bootstrap' && compareVersions(version, '3.4.0') < 0) {
    return { severity: 'medium', message: 'version antérieure à la 3.4.0, failles XSS connues dans les composants JavaScript' };
  }
  return null;
}

function createLibraryFinding(detection, src) {
  var name = detection.library.name;
  var version = detection.version;
  var evidence = { library: name };
  if (version) evidence.version = version;
  evidence.scriptSrc = src.length > maximumSrcLength ? src.slice(0, maximumSrcLength) : src;

  var outdated = classifyLibrary(detection.library.id, version);
  if (outdated) {
    return createFinding(
      'SEC-025',
      'Librairie JavaScript obsolète : ' + name,
      outdated.severity,
      'medium',
      'CWE-1104',
      evidence,
      name + (version ? ' ' + version : '') + ' détecté : ' + outdated.message + '. Détection basée uniquement sur l’URL du script.',
      detection.library.id === 'angularjs'
        ? 'Migrer vers un framework maintenu (Angular, React, Vue…) ; en attendant, limiter l’injection de contenu utilisateur dans les templates.'
        : 'Mettre à jour ' + name + ' vers la dernière version stable et vérifier la compatibilité des plugins qui en dépendent.'
    );
  }

  if (version) return null;

  return createFinding(
    'SEC-025',
    'Librairie JavaScript détectée : ' + name,
    'info',
    'low',
    'CWE-1104',
    evidence,
    name + ' détecté, version non déterminée.',
    'Vérifier manuellement la version de ' + name + ' utilisée et la maintenir à jour.'
  );
}

function evaluateJsLibraries(body) {
  try {
    var $ = cheerio.load(typeof body === 'string' ? body : '');
    var findings = [];
    var seen = {};

    $('script[src]').each(function() {
      if (findings.length >= maximumFindings) return false;

      var src = ($(this).attr('src') || '').trim();
      var detection = src ? detectLibrary(src) : null;
      if (!detection) return;

      // Dédoublonnage : une seule occurrence par couple librairie/version.
      var key = detection.library.id + '|' + (detection.version || '');
      if (seen[key]) return;
      seen[key] = true;

      var finding = createLibraryFinding(detection, src);
      if (finding) findings.push(finding);
    });

    return findings;
  } catch (error) {
    console.warn('Analyse des librairies JavaScript ignorée après une erreur du parseur.');
    return [];
  }
}

module.exports = {
  evaluateJsLibraries: evaluateJsLibraries,
  detectLibrary: detectLibrary,
  classifyLibrary: classifyLibrary
};
