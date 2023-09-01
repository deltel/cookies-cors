import 'dotenv/config';

import express from 'express';
import { v4 as uuid } from 'uuid';
import cookieParser from 'cookie-parser';
import cors from 'cors';

import { signToken, verifyToken } from './token';
import { JwtPayload } from 'jsonwebtoken';

const app = express();
app.use(express.json());
app.use(cookieParser());

const port = process.env.PORT;

app.disable('x-powered-by');

app.get('/v1', (_, res) => {
    res.send('Hello World!');
});

app.options(
    '/v1/login',
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
        methods: ['POST'],
    })
);
app.post(
    '/v1/login',
    cors({
        origin: 'http://localhost:3000',
        exposedHeaders: ['X-CSRF-Token'],
        credentials: true,
        methods: ['POST'],
    }),
    (req, res) => {
        console.log('request', req.body);
        const csrfToken = uuid();
        const jwt = signToken({
            sub: 'user-id',
            role: 'admin',
            csrfToken,
        });

        res.setHeader(
            'Set-Cookie',
            `jwt=${jwt}; Expires=Thu, 31 Oct 2025 07:28:00 GMT; Max-Age=216000; Secure; HttpOnly`
        );
        res.setHeader('X-CSRF-Token', csrfToken);

        res.send({ message: 'Successfully logged in.' });
    }
);

app.options(
    '/v1/protected',
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
        methods: ['GET'],
    })
);
app.get(
    '/v1/protected',
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
        methods: ['GET'],
    }),
    (req, res) => {
        const payload = verifyToken(req.cookies.jwt) as JwtPayload;
        console.log('cookies', req.cookies);
        console.log('payload', payload);
        const csrfToken = req.headers['x-csrf-token'];
        console.log('csrfToken', csrfToken);

        if (payload.csrfToken === csrfToken) {
            return res.send({ message: 'Authenticated user' });
        }
        res.status(401).send({ message: 'Invalid session' });
    }
);

app.listen(port, () => {
    console.log(`Application started on port ${port}`);
});
