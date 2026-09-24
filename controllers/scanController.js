var mongoose = require('mongoose');
var Scan = require('../models/Scan');
var mockFindings = require('../data/mockFindings');

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

    var findings = mockFindings.map(function(finding) { return Object.assign({}, finding); });
    var scan = await Scan.create({
      target: target,
      status: 200,
      findings: findings,
      score: calculateScore(findings)
    });
    res.status(201).json(scan);
  } catch (error) {
    next(error);
  }
}

async function listScans(req, res, next) {
  try {
    var scans = await Scan.find().sort({ createdAt: -1 }).select('target score createdAt findings');
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
    var scan = await Scan.findById(req.params.id);
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
      { _id: req.params.id, 'findings._id': req.params.findingId },
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
    var scan = await Scan.findByIdAndDelete(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan introuvable' });
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}

module.exports = { createScan, listScans, getScan, updateFinding, deleteScan };
