const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const { createUser, findUserByEmail,   updateResetToken,findUserByResetToken, updatePassword } = require("../models/userModel");
const { sendPasswordResetEmail, sendOTPEmail } = require('../services/emailService');
require("dotenv").config();
const pool = require("../db");

const register = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await createUser(name, email, hashedPassword);

    res.status(201).json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ token, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  
  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(200).json({ 
        success: true,
        message: 'If an account exists with this email, a reset link has been sent'
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 3600000); // 1 hour
    
    await updateResetToken(email, token, expiry);
    
    try {
      await sendPasswordResetEmail(user.email, token);
      return res.status(200).json({
        success: true,
        message: 'If an account exists with this email, a reset link has been sent'
      });
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      await updateResetToken(email, null, null);
      return res.status(500).json({
        success: false,
        message: 'Failed to send password reset email'
      });
    }
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred while processing your request'
    });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  
  try {
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    const user = await findUserByResetToken(token);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await updatePassword(user.id, hashedPassword);
    
    return res.status(200).json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred while resetting your password'
    });
  }
};


const checkEmailExists = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ 
        exists: false,
        message: 'No account found with this email'
      });
    }
    return res.status(200).json({ 
      exists: true,
      message: 'Email verified'
    });
  } catch (error) {
    return res.status(500).json({ 
      error: error.message 
    });
  }
};

//Otp Gen


// Add these to your existing auth controller
const generateLoginOTP = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Generate 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = new Date(Date.now() + 3 * 60 * 1000); // 3 minutes

    // Save OTP to user record
    await pool.query(
      'UPDATE users SET otp = $1, otp_expiry = $2 WHERE id = $3',
      [otp, otpExpiry, user.id]
    );

    // Send OTP via email
    await sendOTPEmail(user.email, otp);

    res.status(200).json({ 
      success: true, 
      message: 'OTP sent to your email',
      otpId: user.id // For verification reference
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

const verifyLoginOTP = async (req, res) => {
  const { otpId, otp } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND otp = $2 AND otp_expiry > NOW()',
      [otpId, otp]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired OTP' 
      });
    }

    const user = result.rows[0];
    
    // Clear OTP after successful verification
    await pool.query(
      'UPDATE users SET otp = NULL, otp_expiry = NULL WHERE id = $1',
      [user.id]
    );

    // Generate final auth token
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { 
      expiresIn: '1h' 
    });

    res.status(200).json({ 
      success: true,
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { 
  register, 
  login,
  requestPasswordReset,
  resetPassword,
  checkEmailExists,
  generateLoginOTP,
  verifyLoginOTP
};

