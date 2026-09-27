var mongoose = require('mongoose');
var Scan = require('../models/Scan');
var scanEngine = require('../services/scanEngine');

var severityPenalties = { critical: 30, high: 20, medium: 10, low: 5, info: 0 };

function calculateScore(findings) {
  var penalty = findings.reduce(function(total, finding) {
    return total + (finding.fixed ? 0 : severityPenalties[finding.severity]);
  }, 0);

  return Math.max(0, 100 - penalty);
}

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
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

    var scan = await Scan.create({
      user: req.user._id,
      target: target,
      status: scanResult.status,
      findings: scanResult.findings,
      score: calculateScore(scanResult.findings)
    });
    res.status(201).json(scan);
  } catch (error) {
    next(error);
  }
}

async function listScans(req, res, next) {
  try {
    var scans = await Scan.find({ user: req.user._id }).sort({ createdAt: -1 }).select('target score createdAt findings');
    res.json(scans.map(function(scan) {
      return {
        id: scan._id,
        target: scan.target,
        score: scan.score,
        createdAt: scan.createdAt,
        findingsCount: scan.findings.length
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

module.exports = { createScan, listScans, getScan, updateFinding, deleteScan };
