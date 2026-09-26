var jwt = require('jsonwebtoken');
var User = require('../models/User');

async function protect(req, res, next) {
  var authorization = req.headers.authorization || '';
  var match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match) return res.status(401).json({ error: 'Non authentifié' });

  var decoded;
  try {
    decoded = jwt.verify(match[1], process.env.JWT_SECRET);
  } catch (error) {
    return res.status(401).json({ error: 'Session invalide, reconnectez-vous' });
  }

  try {
    var user = decoded && decoded.id ? await User.findById(decoded.id) : null;
    if (!user) return res.status(401).json({ error: 'Session invalide, reconnectez-vous' });
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'CastError') {
      return res.status(401).json({ error: 'Session invalide, reconnectez-vous' });
    }
    next(error);
  }
}

module.exports = { protect: protect };