const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
const path = require('path');
const pool = require('./config/db');


const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET;


app.get("/login.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post('/register', async (req, res) => {
    const { username, password, email, role } = req.body;

    if (!username || !password || !email || !role) {
        return res.status(400).json({ message: "Kullanıcı adı, şifre, mail ve rol gereklidir" });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);


        pool.query(
            "INSERT INTO users (username, password, email,role) VALUES(?, ?, ?)",
            [username, hashedPassword, email],
            (err, result) => {
                if (err) {
                    return res.status(500).json({ message: "Kayıt hatası", error: err.message });
                }
                res.status(201).json({ message: "Kayıt başarılı", user: result });
            }
        );
    } catch (err) {
        res.status(500).json({ message: "Kayıt hatası", error: err.message });
    }
});



app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Kullanıcı adı ve şifre gereklidir" });
    }

    try {
        pool.query(
            "SELECT * FROM users WHERE username = ?",
            [username],
            async (err, results) => {
                if (err) {
                    return res.status(500).json({ message: "Giriş hatası", error: err.message });
                }

                if (results.length === 0) {
                    return res.status(400).json({ message: "Kullanıcı bulunamadı" });
                }

                const validPassword = await bcrypt.compare(password, results[0].password);
                if (!validPassword) {
                    return res.status(400).json({ message: "Geçersiz şifre" });
                }

                const token = jwt.sign(
                    {
                        id: results[0].id, username: results[0].username
                    },
                    JWT_SECRET,
                    { expiresIn: '1h' }
                );

                res.json({ message: "Giriş başarılı", token });
            }
        );
    } catch (err) {
        res.status(500).json({ message: "Giriş hatası", error: err.message });
    }
});


app.get('/protected', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: "Token gerekli" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Geçersiz veya süresi dolmuş token" });
        }
        res.json({ message: "Token geçerli", user: decoded });
    });
});


app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
    console.log(`Sunucu ${PORT} portunda çalışıyor!`);
});
