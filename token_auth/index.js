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
const AUTH0_CLIENT_ID = 'XCeuiOQiTdXW0oo8HBAVRxhYotX5pfhV';
const AUTH0_CLIENT_SECRET = 'H3QSPM6htEm9rerUAwGAqi0Nrp4VOUa8ZKdylqH-7P-_Edn9ToKnI3K-R4dKx9Z3';
const AUTH0_AUDIENCE = 'https://dev-dip3jzvktcwcx001.us.auth0.com/api/v2/';
const AUTH0_CONNECTION = 'Username-Password-Authentication';
const REDIRECT_URI = 'http://localhost:3000/callback';

const client = jwksClient({
    jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
});

let pemPublicKey = null;
let pemKeyFetchTime = null;
const PEM_CACHE_TTL = 3600000;

function getKeyFromJWKS(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            return callback(err);
        }
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

async function getPEMPublicKey() {
    if (pemPublicKey && pemKeyFetchTime && (Date.now() - pemKeyFetchTime < PEM_CACHE_TTL)) {
        return pemPublicKey;
    }

    try {
        // Формуємо URL для отримання PEM ключа
        // Формат: https://[DOMAIN]/pem або https://[API_DOMAIN]/pem
        const pemUrl = `https://${AUTH0_DOMAIN}/pem`;
        
        console.log(`Отримання PEM ключа з ${pemUrl}`);
        const response = await axios.get(pemUrl, {
            timeout: 5000,
            headers: {
                'Accept': 'application/x-pem-file'
            }
        });

        pemPublicKey = response.data;
        pemKeyFetchTime = Date.now();
        
        console.log('PEM ключ успішно отримано та закешовано');
        return pemPublicKey;
    } catch (error) {
        console.error('Помилка при отриманні PEM ключа:', error.message);
        // Якщо є старий ключ в кеші, використовуємо його
        if (pemPublicKey) {
            console.log('Використання закешованого PEM ключа');
            return pemPublicKey;
        }
        throw error;
    }
}

function getKey(header, callback) {
    // Спочатку намагаємося отримати ключ через JWKS
    getKeyFromJWKS(header, (err, key) => {
        if (!err && key) {
            return callback(null, key);
        }
        
        // Якщо JWKS не працює, використовуємо PEM
        console.log('JWKS не працює, використовуємо PEM ключ');
        getPEMPublicKey()
            .then(pemKey => {
                callback(null, pemKey);
            })
            .catch(pemErr => {
                callback(pemErr || err);
            });
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

// Перевірка токена через JWKS
async function validateAuth0TokenWithJWKS(token) {
    return new Promise((resolve, reject) => {
        jwt.verify(token, getKeyFromJWKS, {
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

// Перевірка токена через PEM публічний ключ
async function validateAuth0TokenWithPEM(token) {
    try {
        const publicKey = await getPEMPublicKey();
        
        return new Promise((resolve, reject) => {
            jwt.verify(token, publicKey, {
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
    } catch (error) {
        throw new Error(`Помилка перевірки через PEM: ${error.message}`);
    }
}

// Універсальна перевірка токена з fallback між JWKS та PEM
async function validateAuth0Token(token) {
    // Спочатку намагаємося перевірити через JWKS
    try {
        const decoded = await validateAuth0TokenWithJWKS(token);
        console.log('✓ Токен перевірено через JWKS');
        return decoded;
    } catch (jwksError) {
        console.log('JWKS перевірка не вдалася, спроба через PEM...', jwksError.message);
        
        // Якщо JWKS не працює, використовуємо PEM
        try {
            const decoded = await validateAuth0TokenWithPEM(token);
            console.log('✓ Токен перевірено через PEM');
            return decoded;
        } catch (pemError) {
            console.error('PEM перевірка не вдалася:', pemError.message);
            throw new Error(`Помилка перевірки токена: JWKS (${jwksError.message}), PEM (${pemError.message})`);
        }
    }
}

// Endpoint для редіректу на Auth0 SSO
app.get('/login', (req, res) => {
    const authUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
    authUrl.searchParams.set('client_id', AUTH0_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('response_mode', 'query');
    authUrl.searchParams.set('scope', 'openid profile email');
    
    console.log('Редірект на Auth0 SSO:', authUrl.toString());
    res.redirect(authUrl.toString());
});

// Callback endpoint для обробки authorization code
app.get('/callback', async (req, res) => {
    const { code, error, error_description } = req.query;

    if (error) {
        console.error('Помилка авторизації:', error, error_description);
        return res.redirect(`/?error=${encodeURIComponent(error_description || error)}`);
    }

    if (!code) {
        return res.redirect('/?error=authorization_code_not_provided');
    }

    try {
        // Обмін authorization code на токени
        const tokenResponse = await axios.post(
            `https://${AUTH0_DOMAIN}/oauth/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: AUTH0_CLIENT_ID,
                client_secret: AUTH0_CLIENT_SECRET,
                code: code,
                redirect_uri: REDIRECT_URI
            }),
            {
                headers: {
                    'content-type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, id_token, refresh_token } = tokenResponse.data;

        // Декодування ID токену для отримання інформації про користувача
        let userInfo;
        try {
            userInfo = jwt.decode(id_token);
        } catch (e) {
            userInfo = {};
        }

        // Збереження інформації в сесії
        req.session.auth0Token = access_token;
        req.session.refreshToken = refresh_token;
        req.session.idToken = id_token;
        req.session.username = userInfo.name || userInfo.email || userInfo.sub;
        req.session.email = userInfo.email;
        req.session.userId = userInfo.sub;

        console.log('Успішна автентифікація через SSO:', req.session.email);

        // Перенаправлення на головну сторінку
        res.redirect('/');
    } catch (error) {
        console.error('Помилка обміну code на токени:', error.response?.data || error.message);
        const errorMsg = error.response?.data?.error_description || error.message;
        res.redirect(`/?error=${encodeURIComponent(errorMsg)}`);
    }
});

app.get('/', async (req, res) => {
    if (req.session.auth0Token) {
        try {
            const decoded = await validateAuth0Token(req.session.auth0Token);
            
            return res.json({
                username: req.session.username || decoded.email || decoded.sub,
                email: req.session.email || decoded.email,
                logout: 'http://localhost:3000/logout',
                verificationMethod: 'JWKS/PEM (auto fallback)'
            });
        } catch (error) {
            console.error('Токен невалідний:', error.message);
            req.session = {};
            sessions.set(req.sessionId, {});
        }
    }
    
    res.sendFile(path.join(__dirname+'/index.html'));
});

// Endpoint для тестування перевірки через JWKS
app.get('/api/verify/jwks', async (req, res) => {
    const token = req.session?.auth0Token || req.query.token;
    
    if (!token) {
        return res.status(400).json({ error: 'Токен не надано' });
    }

    try {
        const decoded = await validateAuth0TokenWithJWKS(token);
        res.json({
            success: true,
            method: 'JWKS',
            decoded: {
                sub: decoded.sub,
                email: decoded.email,
                aud: decoded.aud,
                iss: decoded.iss,
                exp: decoded.exp,
                iat: decoded.iat
            }
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            method: 'JWKS',
            error: error.message
        });
    }
});

// Endpoint для тестування перевірки через PEM
app.get('/api/verify/pem', async (req, res) => {
    const token = req.session?.auth0Token || req.query.token;
    
    if (!token) {
        return res.status(400).json({ error: 'Токен не надано' });
    }

    try {
        const decoded = await validateAuth0TokenWithPEM(token);
        res.json({
            success: true,
            method: 'PEM',
            decoded: {
                sub: decoded.sub,
                email: decoded.email,
                aud: decoded.aud,
                iss: decoded.iss,
                exp: decoded.exp,
                iat: decoded.iat
            },
            pemKeyUrl: `https://${AUTH0_DOMAIN}/pem`
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            method: 'PEM',
            error: error.message
        });
    }
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
