const db = require('../config/db');

const createUser = (user, callback) => {
    const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
    db.query(sql, [user.name, user.email, user.password, user.role], callback);
};

const findUserByEmail = (email, callback) => {
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], callback);
};

const updateUserPassword = (userId, hashedPassword, callback) => {
    const sql = 'UPDATE users SET password = ? WHERE id = ?';
    db.query(sql, [hashedPassword, userId], callback);
};

const findUserById = (id, callback) => {
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [id], (err, results) => {
        if (err) return callback(err);
        callback(null, results[0]);
    });
};
const user = await userModel.findByUsername(username);

if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Geçersiz kullanıcı adı veya şifre" });
}


module.exports = {
    createUser,
    findUserByEmail,
    updateUserPassword,
    findUserById,
};
