require('dotenv').config();

var express = require('express');
var cors = require('cors');
var mongoose = require('mongoose');
var scansRouter = require('./routes/scans');
var authRouter = require('./routes/auth');

var app = express();

app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json({ limit: '100kb' }));

app.get('/api/health', function(req, res) {
  var isConnected = mongoose.connection.readyState === 1;

  res.json({
    status: isConnected ? 'ok' : 'error',
    service: 'seculens-backend',
    database: isConnected ? 'connected' : 'disconnected'
  });
});

app.use('/api/auth', authRouter);
app.use('/api/scans', scansRouter);

// Les erreurs inconnues restent toujours des réponses JSON sans stack trace.
app.use(function(req, res) {
  res.status(404).json({ error: 'Route introuvable' });
});

app.use(function(err, req, res, next) {
  if (err instanceof SyntaxError && err.status === 400 && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON invalide' });
  }

  var status = err.status || 500;
  res.status(status).json({ error: status === 500 ? 'Erreur serveur' : err.message });
});

module.exports = app;
