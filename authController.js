const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const userModel = require('../models/userModel');
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
    }
});


const JWT_SECRET = process.env.JWT_SECRET;


exports.register = (req, res) => {
    const { name, email, password, role } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({ message: 'Şifre hashlenemedi' });

        userModel.createUser({ name, email, password: hashedPassword, role }, (err, result) => {
            if (err) return res.status(500).json({ message: 'Kullanıcı oluşturulamadı', error: err });
            res.status(201).json({ message: 'Kayıt başarılı' });
        });
    });
};


exports.login = (req, res) => {
    const { email, password } = req.body;

    userModel.findUserByEmail(email, (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: 'Kullanıcı bulunamadı' });
        }

        const user = results[0];

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({ message: 'Şifre hatalı' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                JWT_SECRET,
                { expiresIn: '1h' }
            );


            res.json({ token });
        });
    });
};


exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    userModel.findUserByEmail(email, (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ message: 'Kullanıcı bulunamadı' });
        }

        const user = results[0];

        const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const resetLink = `http://localhost:5000/api/auth/reset-password/${resetToken}`;

        const mailOptions = {
            from: process.env.MAIL_FROM,
            to: email,
            subject: 'Şifre Sıfırlama Talebi',
            text: `Şifrenizi sıfırlamak için şu linki tıklayın: ${resetLink}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: 'E-posta gönderilemedi', error });
            }
            res.json({ message: 'Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.' });
        });
    });
};



exports.resetPassword = (req, res) => {
    const { token, newPassword } = req.body;

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(400).json({ message: 'Geçersiz veya süresi dolmuş token' });
        }

        const userId = decoded.id;

        bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ message: 'Şifre hashlenemedi' });
            }

            userModel.updateUserPassword(userId, hashedPassword, (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Şifre güncellenemedi', error: err });
                }
                res.json({ message: 'Şifreniz başarıyla güncellenmiştir' });
            });
        });
    });
};
