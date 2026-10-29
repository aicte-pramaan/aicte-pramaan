const jwt = require('jsonwebtoken');

// Verify JWT Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expecting 'Bearer <token>'

    if (!token) {
        return res.status(401).json({ error: 'Access Denied: No Token Provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'super_secure_jwt_secret_for_aicte_2026');
        req.user = decoded; // Contains { username, role }
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or Expired Token' });
    }
};

// Enforce Role-Based Access Control
const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden: Insufficient Role Permissions (RBAC Enforced)' });
        }
        next();
    };
};

module.exports = { authenticateToken, requireRole };