var mongoose = require('mongoose');

var findingSchema = new mongoose.Schema({
  ruleId: { type: String, required: true },
  title: { type: String, required: true },
  severity: { type: String, enum: ['critical', 'high', 'medium', 'low', 'info'], required: true },
  confidence: { type: String, enum: ['high', 'medium', 'low'], required: true },
  cwe: { type: String, required: true },
  evidence: { type: mongoose.Schema.Types.Mixed },
  description: { type: String, required: true },
  remediation: { type: String, required: true },
  fixed: { type: Boolean, default: false }
}, { _id: true });

var scanSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  target: { type: String, required: true, match: /^https?:\/\// },
  status: { type: Number, required: true },
  score: { type: Number, required: true, min: 0, max: 100 },
  findings: { type: [findingSchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.model('Scan', scanSchema);
