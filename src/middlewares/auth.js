const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth');

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;

    
    if (!authHeader)
        return res.status(401).send({ error: 'No token provider' });

    // Bearer 57834752984j5o34i24857342j43h52i34897

    const parts = authHeader.split(' ');

    if (!parts.length === 2)
        return res.status(401).send({ error: 'Token error' });


    const [ scheme, token ] = parts;

    if (!/^Bearer$/i.test(scheme))
        return res.status(401).send({ error: 'Token malformatted' });

    jwt.verify(token, authConfig.secret, (err, decoded) => {
        if (err) return res.status(401).send({  error: 'Token invalid' });

        req.userId = decoded.id;
        return next();
    });
};