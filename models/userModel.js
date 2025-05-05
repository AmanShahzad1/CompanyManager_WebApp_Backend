const pool = require("../db");

const createUser = async (name, email, hashedPassword) => {
  const result = await pool.query(
    "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
    [name, email, hashedPassword]
  );
  return result.rows[0];
};

const findUserByEmail = async (email) => {
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
  return result.rows[0];
};


const updateResetToken = async (email, token, expiry) => {
  await pool.query(
    "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3",
    [token, expiry, email]
  );
};

const findUserByResetToken = async (token) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > NOW()",
    [token]
  );
  return result.rows[0];
};

const updatePassword = async (userId, hashedPassword) => {
  await pool.query(
    "UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2",
    [hashedPassword, userId]
  );
};


module.exports = { 
  createUser, 
  findUserByEmail,
  updateResetToken,
  findUserByResetToken,
  updatePassword
};
