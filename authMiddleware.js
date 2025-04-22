const jwt = require('jsonwebtoken');

const authenticateJWT = (req, res, next) => {

    const token = req.header('Authorization') && req.header('Authorization').startsWith('Bearer ')
        ? req.header('Authorization').split(' ')[1]
        : null;

    if (!token) {
        return res.status(403).json({ message: 'Token bulunamadı. Lütfen giriş yapınız.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Geçersiz token veya süresi dolmuş' });
        }

        req.user = decoded;
        next();
    });
};

module.exports = authenticateJWT;
