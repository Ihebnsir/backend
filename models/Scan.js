var mongoose = require('mongoose');

// Explication générée par l'IA ; les champs restent à null si l'IA n'a pas pu répondre.
var aiExplanationSchema = new mongoose.Schema({
  simpleExplanation: { type: String, default: null },
  realWorldRisk: { type: String, default: null },
  fixSteps: { type: String, default: null }
}, { _id: false });

// Catégorie OWASP Top 10 2021 (affichage seulement), absente si la règle n'est pas classée.
var owaspSchema = new mongoose.Schema({
  code: { type: String, required: true },
  name: { type: String, required: true }
}, { _id: false });

// Baisse significative du score par rapport au scan précédent du même target.
var scoreRegressionSchema = new mongoose.Schema({
  previousScore: { type: Number, required: true },
  previousScanId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scan', required: true },
  drop: { type: Number, required: true }
}, { _id: false });

var findingSchema = new mongoose.Schema({
  ruleId: { type: String, required: true },
  title: { type: String, required: true },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  confidence: { type: String, enum: ['high', 'medium', 'low'], required: true },
  cwe: { type: String, required: true },
  owasp: { type: owaspSchema, default: undefined },
  evidence: { type: mongoose.Schema.Types.Mixed },
  description: { type: String, required: true },
  remediation: { type: String, required: true },
  fixed: { type: Boolean, default: false },
  // null tant que le traitement IA de ce finding n'est pas terminé.
  aiExplanation: { type: aiExplanationSchema, default: null }
}, { _id: true });

var scanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  target: { type: String, required: true, match: /^https?:\/\// },
  status: { type: Number, required: true },
  score: { type: Number, required: true, min: 0, max: 100 },
  // Version des règles ayant produit ce scan (absente sur les scans antérieurs à son ajout).
  scannerVersion: { type: String },
  findings: { type: [findingSchema], default: [] },
  // Absent s'il n'y a pas de scan précédent ou si la baisse est inférieure au seuil.
  scoreRegression: { type: scoreRegressionSchema, default: undefined }
}, { timestamps: true });

module.exports = mongoose.model('Scan', scanSchema);
