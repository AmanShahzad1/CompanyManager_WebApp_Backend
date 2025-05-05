const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.APP_URL}/pages/reset-password?token=${token}`;
  
  const msg = {
    to: email,
    from: process.env.EMAIL_FROM,
    replyTo: process.env.EMAIL_REPLY_TO,
    subject: 'Password Reset Request',
    text: `Please click the following link to reset your password: ${resetUrl}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb;">Password Reset Request</h1>
        <p>Hello,</p>
        <p>We received a request to reset your password. Click the button below to reset it:</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #2563eb; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
        <p>If you didn't request this, please ignore this email.</p>
        <p>This link will expire in 1 hour.</p>
      </div>
    `,
  };

  try {
    await sgMail.send(msg);
    console.log('Password reset email sent to', email);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    if (error.response) {
      console.error('SendGrid response:', error.response.body);
    }
    throw new Error('Failed to send password reset email');
  }
};

const sendOTPEmail = async (email, otp) => {
  const msg = {
    to: email,
    from: process.env.EMAIL_FROM,
    subject: 'Your Login OTP',
    text: `Your OTP is: ${otp}\nThis code expires in 3 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #2563eb;">Login Verification</h1>
        <p>Your one-time password (OTP) is:</p>
        <div style="font-size: 24px; font-weight: bold; margin: 20px 0; color: #2563eb;">
          ${otp}
        </div>
        <p style="color: #64748b;">This code will expire in 3 minutes.</p>
      </div>
    `
  };
  await sgMail.send(msg);
};

module.exports = { sendPasswordResetEmail, sendOTPEmail };