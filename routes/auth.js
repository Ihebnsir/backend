var express = require('express');
var controller = require('../controllers/authController');
var router = express.Router();

router.post('/register', controller.register);
router.post('/login', controller.login);
router.post('/resend-verification', controller.resendVerification);
router.post('/verify-email', controller.verifyEmail);
router.post('/forgot-password', controller.forgotPassword);
router.post('/reset-password', controller.resetPassword);

module.exports = router;