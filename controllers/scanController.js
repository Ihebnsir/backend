var mongoose = require('mongoose');
var Scan = require('../models/Scan');
var scanEngine = require('../services/scanEngine');
var aiExplain = require('../services/aiExplain');

var severityPenalties = { critical: 30, high: 20, medium: 10, low: 5, info: 0 };
// Baisse minimale (en points) pour signaler une régression par rapport au scan précédent.
var regressionThreshold = 15;

function calculateScore(findings) {
  var penalty = findings.reduce(function(total, finding) {
    return total + (finding.fixed ? 0 : severityPenalties[finding.severity]);
  }, 0);

  return Math.max(0, 100 - penalty);
}

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

// Tâche de fond lancée après la réponse HTTP : demande les explications IA
// puis les enregistre sur chaque finding, retrouvé par son _id.
async function attachAiExplanations(scan) {
  if (!scan.findings.length) return;

  var explanations = await aiExplain.explainFindings(scan.findings);
  var update = {};
  var arrayFilters = [];

  scan.findings.forEach(function(finding, index) {
    // Même en cas d'échec (champs à null), on enregistre l'objet : cela signale que le traitement est terminé.
    update['findings.$[f' + index + '].aiExplanation'] = explanations[index];
    var filter = {};
    filter['f' + index + '._id'] = finding._id;
    arrayFilters.push(filter);
  });

  // Si le scan a été supprimé entre-temps, cette mise à jour ne fait simplement rien.
  await Scan.updateOne({ _id: scan._id }, { $set: update }, { arrayFilters: arrayFilters });
}

// Compare le nouveau score au dernier scan du même utilisateur sur le même target.
// Le projet ne normalise pas les URL : la comparaison du target est stricte
// (http://site.fr et http://site.fr/ sont donc deux targets différents).
// Ne lève jamais d'erreur : en cas d'échec, le scan est créé sans scoreRegression.
async function findScoreRegression(userId, target, newScore) {
  try {
    var previousScan = await Scan.findOne({ user: userId, target: target })
      .sort({ createdAt: -1 })
      .select('score');
    if (!previousScan) return null;

    var drop = previousScan.score - newScore;
    if (drop < regressionThreshold) return null;

    return { previousScore: previousScan.score, previousScanId: previousScan._id, drop: drop };
  } catch (error) {
    console.error('Recherche du scan précédent impossible, scan créé sans comparaison : ' + error.message);
    return null;
  }
}

async function createScan(req, res, next) {
  try {
    var keys = Object.keys(req.body || {});
    var target = req.body && req.body.target;

    if (keys.length !== 1 || keys[0] !== 'target' || typeof target !== 'string' || !/^https?:\/\//.test(target)) {
      return res.status(400).json({ error: 'Le body doit contenir uniquement un target HTTP ou HTTPS valide' });
    }

    var scanResult = await scanEngine.runScan(target);
    if (scanResult.error) {
      if (scanResult.error.code === 'SSRF_REJECTED') {
        return res.status(400).json({
          error: 'Cible non autorisée pour des raisons de sécurité (adresse privée ou réservée).'
        });
      }

      return res.status(422).json({
        error: 'Impossible de joindre la cible. Vérifiez que l’URL est accessible.'
      });
    }

    var score = calculateScore(scanResult.findings);
    var scoreRegression = await findScoreRegression(req.user._id, target, score);

    var scan = await Scan.create({
      user: req.user._id,
      target: target,
      status: scanResult.status,
      findings: scanResult.findings,
      score: score,
      scannerVersion: scanEngine.SCANNER_VERSION,
      scoreRegression: scoreRegression || undefined
    });
    res.status(201).json(scan);

    // Lancé sans await : le client a déjà sa réponse, l'IA travaille en arrière-plan.
    // Le .catch empêche une erreur de l'IA ou de MongoDB de faire planter le serveur.
    attachAiExplanations(scan).catch(function(error) {
      console.error('Enregistrement des explications IA impossible pour le scan ' + scan._id + ' : ' + error.message);
    });
  } catch (error) {
    next(error);
  }
}

// Indique si toutes les explications IA d'un scan sont prêtes (même vides en cas d'échec de l'IA).
async function getAiStatus(req, res, next) {
  if (!isValidId(req.params.id)) return res.status(400).json({ error: 'Identifiant invalide' });

  try {
    var scan = await Scan.findOne({ _id: req.params.id, user: req.user._id }).select('findings.aiExplanation');
    if (!scan) return res.status(404).json({ error: 'Scan introuvable' });

    var ready = scan.findings.every(function(finding) {
      return Boolean(finding.aiExplanation);
    });
    res.json({ ready: ready });
  } catch (error) {
    next(error);
  }
}

async function listScans(req, res, next) {
  try {
    var scans = await Scan.find({ user: req.user._id }).sort({ createdAt: -1 }).select('target score createdAt findings scannerVersion');
    res.json(scans.map(function(scan) {
      return {
        id: scan._id,
        target: scan.target,
        score: scan.score,
        createdAt: scan.createdAt,
        findingsCount: scan.findings.length,
        scannerVersion: scan.scannerVersion || null
      };
    }));
  } catch (error) {
    next(error);
  }
}

async function getScan(req, res, next) {
  if (!isValidId(req.params.id)) return res.status(400).json({ error: 'Identifiant invalide' });

  try {
    var scan = await Scan.findOne({ _id: req.params.id, user: req.user._id });
    if (!scan) return res.status(404).json({ error: 'Scan introuvable' });
    res.json(scan);
  } catch (error) {
    next(error);
  }
}

async function updateFinding(req, res, next) {
  if (!isValidId(req.params.id) || !isValidId(req.params.findingId)) return res.status(400).json({ error: 'Identifiant invalide' });
  if (!req.body || Object.keys(req.body).length !== 1 || typeof req.body.fixed !== 'boolean') {
    return res.status(400).json({ error: 'Le body doit contenir uniquement un booléen fixed' });
  }

  try {
    var scan = await Scan.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id, 'findings._id': req.params.findingId },
      { $set: { 'findings.$.fixed': req.body.fixed } },
      { new: true, runValidators: true }
    );
    if (!scan) return res.status(404).json({ error: 'Scan ou finding introuvable' });

    scan.score = calculateScore(scan.findings);
    await scan.save();
    res.json(scan);
  } catch (error) {
    next(error);
  }
}

async function deleteScan(req, res, next) {
  if (!isValidId(req.params.id)) return res.status(400).json({ error: 'Identifiant invalide' });

  try {
    var scan = await Scan.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    if (!scan) return res.status(404).json({ error: 'Scan introuvable' });
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}

module.exports = { createScan, listScans, getScan, getAiStatus, updateFinding, deleteScan };
