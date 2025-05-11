const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const config = require('../config');

const prisma = new PrismaClient();
const app = express.Router();

// Middleware to check authentication
async function ensureAuthenticated(req, res, next) {
    const tokenFromHeader = req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.split(' ')[1]
        : null;
    
    const tokenFromCookie = req.cookies?.accessToken;
    const token = tokenFromHeader || tokenFromCookie;

    if (!token) {
        return res.status(401).json({ message: 'Access Token not found' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        req.accessToken = { value: token, exp: decoded.exp };
        req.user = { id: decoded.userId }; 

        const invalidToken = await prisma.invalidToken.findFirst({
            where: { token }
        });

        if (invalidToken) {
            return res.status(401).json({ message: 'Access Token is no longer valid' });
        }

        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        return res.status(401).json({ message: 'Access Token not valid or expired' });
    }
}


// Get current authenticated user
app.get('/users/current', ensureAuthenticated, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: req.user.id }, // Use decoded user ID
            select: {
                id: true,
                name: true,
                email: true,
                image:true
            }
        });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

module.exports = app;
