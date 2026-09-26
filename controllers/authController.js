var bcrypt = require('bcryptjs');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var User = require('../models/User');
var sendEmail = require('../utils/mailer').sendEmail;

var resetPasswordMessage = 'Si cet email existe, un lien a été envoyé';

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function createToken(userId) {
  return jwt.sign({ id: userId.toString() }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function userResponse(user) {
  return { id: user._id, email: user.email };
}

async function register(req, res, next) {
  var email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  var password = req.body && req.body.password;

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Veuillez fournir une adresse email valide' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères' });
  }

  try {
    var existingUser = await User.findOne({ email: email });
    if (existingUser) return res.status(409).json({ error: 'Cette adresse email est déjà utilisée' });

    var hashedPassword = await bcrypt.hash(password, 12);
    var user = await User.create({ email: email, password: hashedPassword });
    res.status(201).json({ token: createToken(user._id), user: userResponse(user) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'Cette adresse email est déjà utilisée' });
    next(error);
  }
}

async function login(req, res, next) {
  var email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  var password = req.body && req.body.password;

  try {
    var user = await User.findOne({ email: email }).select('+password');
    var passwordMatches = user && typeof password === 'string'
      ? await bcrypt.compare(password, user.password)
      : false;

    if (!passwordMatches) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    res.json({ token: createToken(user._id), user: userResponse(user) });
  } catch (error) {
    next(error);
  }
}

async function forgotPassword(req, res, next) {
  var email = req.body && typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';

  try {
    var user = await User.findOne({ email: email });
    if (!user) return res.status(200).json({ message: resetPasswordMessage });

    var resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = hashResetToken(resetToken);
    user.resetPasswordExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    var resetUrl = 'http://localhost:3000/reset-password/' + resetToken;
    var html = '<p>Vous avez demandé à réinitialiser le mot de passe de votre compte SecuLens.</p>' +
      '<p><a href="' + resetUrl + '">Réinitialiser mon mot de passe</a></p>' +
      '<p>Ce lien expire dans 1 heure. Ignorez cet email si vous n’êtes pas à l’origine de cette demande.</p>';

    sendEmail(email, 'Réinitialisation de votre mot de passe SecuLens', html);
    res.status(200).json({ message: resetPasswordMessage });
  } catch (error) {
    next(error);
  }
}

async function resetPassword(req, res, next) {
  var token = req.body && req.body.token;
  var newPassword = req.body && req.body.newPassword;

  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères' });
  }
  if (newPassword.length > 72 || Buffer.byteLength(newPassword, 'utf8') > 72) {
    return res.status(400).json({ error: 'Le mot de passe ne doit pas dépasser 72 caractères' });
  }
  if (typeof token !== 'string' || !token) {
    return res.status(400).json({ error: 'Lien invalide ou expiré' });
  }

  try {
    var hashedToken = hashResetToken(token);
    var matchingUser = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() }
    }).select('_id');

    if (!matchingUser) return res.status(400).json({ error: 'Lien invalide ou expiré' });

    var hashedPassword = await bcrypt.hash(newPassword, 12);
    var updatedUser = await User.findOneAndUpdate(
      {
        _id: matchingUser._id,
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: new Date() }
      },
      {
        $set: { password: hashedPassword },
        $unset: { resetPasswordToken: 1, resetPasswordExpires: 1 }
      },
      { new: true, runValidators: true }
    );

    if (!updatedUser) return res.status(400).json({ error: 'Lien invalide ou expiré' });
    res.status(200).json({ message: 'Mot de passe réinitialisé avec succès' });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register: register,
  login: login,
  forgotPassword: forgotPassword,
  resetPassword: resetPassword
};