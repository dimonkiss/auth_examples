const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const port = 3000;
const fs = require('fs');

const AUTH0_DOMAIN = 'dev-dip3jzvktcwcx001.us.auth0.com';
const AUTH0_CLIENT_ID = 'O9Ur7t5HZPtfOdil7e86CRTNxwAQHb4P';
const AUTH0_CLIENT_SECRET = 'ssV-J0R5otVj1e3XV007QfVWmRv_bp5h0eCVYLXdIp53uN430B73ygYnOyTcPXhj';
const AUTH0_AUDIENCE = 'https://dev-dip3jzvktcwcx001.us.auth0.com/api/v2/';
const AUTH0_CONNECTION = 'Username-Password-Authentication';

const client = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            const sessionsPath = path.join(__dirname, 'sessions.json');
            this.#sessions = fs.readFileSync(sessionsPath, 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        const sessionsPath = path.join(__dirname, 'sessions.json');
        fs.writeFileSync(sessionsPath, JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

async function validateAuth0Token(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKey, {
            audience: AUTH0_AUDIENCE,
            issuer: `https://${AUTH0_DOMAIN}/`,
            algorithms: ['RS256']
        }, (err, decoded) => {
            if (err) {
                reject(err);
            } else {
                resolve(decoded);
            }
        });
    });
}

app.get('/', async (req, res) => {
    if (req.session.auth0Token) {
        try {
            const decoded = await validateAuth0Token(req.session.auth0Token);
            
            return res.json({
                username: req.session.username || decoded.email || decoded.sub,
                email: req.session.email || decoded.email,
                logout: 'http://localhost:3000/logout'
            });
        } catch (error) {
            console.error('Токен невалідний:', error.message);
            req.session = {};
            sessions.set(req.sessionId, {});
        }
    }
    
    res.sendFile(path.join(__dirname+'/index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ error: 'Email та пароль обов\'язкові' });
    }

    try {
        const response = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'password',
                username: login,
                password: password,
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                connection: AUTH0_CONNECTION,
                audience: AUTH0_AUDIENCE,
                scope: 'openid profile email offline_access'
            }),
            {
                headers: {
                    'content-type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, id_token, refresh_token } = response.data;

        let userInfo;
        try {
            userInfo = jwt.decode(id_token);
        } catch (e) {
            userInfo = {};
        }

        req.session.auth0Token = access_token;
        req.session.refreshToken = refresh_token;
        req.session.username = userInfo.name || userInfo.email || userInfo.sub;
        req.session.email = userInfo.email;
        req.session.userId = userInfo.sub;

        res.json({ 
            token: req.sessionId,
            username: req.session.username,
            email: req.session.email
        });
    } catch (error) {
        console.error('Помилка автентифікації Auth0:', error.response?.data || error.message);
        
        if (error.response && error.response.status === 403) {
            return res.status(403).json({ 
                error: 'Помилка автентифікації. Перевірте email та пароль.' 
            });
        }
        
        res.status(401).json({ 
            error: 'Помилка автентифікації. Спробуйте ще раз.' 
        });
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
