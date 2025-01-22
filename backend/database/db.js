import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

let conn;

export async function DB_Connection() {
  try {
    conn = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });

    console.log('Connected to MySQL as ID:', conn.threadId);
  } catch (error) {
    console.error('[ERROR] Connection to MySQL database failed:', error.message);
    process.exit(1);
  }
}

export const insertUser = async (userData) => {
  const query = `
    INSERT INTO users (fullname, email, password, token, verificationCode)
    VALUES (?, ?, ?, ?, ?)
  `;

  try {
    const [result] = await conn.execute(query, [
      userData.fullname,
      userData.email,
      userData.password,
      userData.token,
      userData.verificationCode,
    ]);

    console.log('User inserted with ID:', result.insertId);
    return result;
  } catch (error) {
    console.error('Error inserting user:', error.message);
    throw error;
  }
};

export const selectUserByEmail = async (email) => {
  const query = `SELECT * FROM users WHERE email = ? LIMIT 1`;

  try {
    const [rows] = await conn.execute(query, [email]);
    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error('Error selecting user:', error.message);
    throw error;
  }
};

export const insertNewPassword = async (password, email) => {
  const query = `UPDATE users SET password = ? WHERE email = ?`;

  try {
    const [rows] = await pool.execute(query, [password, email]);
    return rows.affectedRows === 0;
  } catch (error) {
    console.error('Error selecting user:', error.message);
    throw error;
  }
};
