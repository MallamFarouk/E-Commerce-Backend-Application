const jwt = require('jsonwebtoken');
require('dotenv').config();

function auth(req, res, next) {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid Token' });
    }
}

function authRole(role){
    return (req, res, next)=>{
        if (req.user.role != role){
            return res.status(403).json({ message: 'Access denied' });
        }
        next()
    }

}

module.exports = {auth, authRole};
