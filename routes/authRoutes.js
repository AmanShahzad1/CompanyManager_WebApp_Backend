const express = require("express");
const { register, login, requestPasswordReset, resetPassword, checkEmailExists, generateLoginOTP, verifyLoginOTP } = require("../controllers/authController");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post('/forgot-password', requestPasswordReset);
router.post('/reset-password', resetPassword);
router.post('/check-email', checkEmailExists);
router.post('/generate-otp', generateLoginOTP);
router.post('/verify-otp', verifyLoginOTP);

module.exports = router;
