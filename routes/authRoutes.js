const express = require('express');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken')
const config = require('../config')
const cookieParser = require('cookie-parser');
const prisma = new PrismaClient();
const app = express.Router();


/** ___________________________________________________________________________________________________________________
 *                                                      REGISTER
*/


// Strong password validation function
const isPasswordStrong = (password) => {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/;
    return regex.test(password);
};


app.post('/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Check if all fields are filled
        if (!name || !email || !password) {
            return res.status(422).json({ message: 'Please fill in all fields' });
        }

        // Validate password strength
        if (!isPasswordStrong(password)) {
            return res.status(400).json({ 
                message: 'Password must be at least 8 characters long, include one uppercase letter, one lowercase letter, and one special character.'
            });
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Store user in the database
        const newUser = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
                role: role ?? 'USER'
            },
        });
        return res.status(201).json({ message: 'User registered successfully', id: newUser.id });
    } catch (error) {
        console.error('Registration error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

/** ___________________________________________________________________________________________________________________
 *                                                      LOGIN
*/

app.post('/auth/login', async(req,res) => {
    try {
        const { email, password } = req.body;

        // Check if email and password are provided
        if (!email || !password) {
            return res.status(422).json({ message: 'Please fill in all fields (email, password)' });
        }

        // Find user in database
        const user = await prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            return res.status(401).json({ message: 'Email or password is invalid' });
        }

        // Compare hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Email or password is invalid' });
        }

        // Generate JWT token
        const accessToken = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET, // Ensure you have JWT_SECRET in your .env file
            { subject: 'accessApi', expiresIn: '1h' }
        );

        const refreshToken = jwt.sign(
            { userId: user.id },
            process.env.REFRESH_TOKEN_SECRET,
            { subject: 'refreshToken', expiresIn: '1w' }
        );

        
        
        // Store refresh token in database (without deleting old ones)
        await prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId: user.id,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 1 week expiry
            }
        });

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 60 * 1000, // 1 hour
          });
          
          res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
          });
          
          return res.status(200).json({ id: user.id, name: user.name, email: user.email });

        

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
})

/** ___________________________________________________________________________________________________________________
 *                                                      LOGOUT
*/

app.post('/auth/logout', ensureAuthenticated, async (req, res) => {
    try {
        await prisma.refreshToken.deleteMany({
            where: { userId: req.user.id }
        });

        await prisma.invalidToken.create({
            data: {
                token: req.accessToken.value,
                userId: req.user.id,
                expiresAt: new Date(req.accessToken.exp * 1000)
            }
        });

        res.clearCookie("accessToken", {
            httpOnly: true,
            sameSite: "strict",
            secure: true,
          });
      
          res.clearCookie("refreshToken", {
            httpOnly: true,
            sameSite: "strict",
            secure: true,
          });
          
        return res.status(204).send();

    } catch (error) {
        console.error('Logout error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

/** ___________________________________________________________________________________________________________________
 *                                                        REFRESH TOKEN
*/

app.post('/auth/refresh-token', async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;

        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh token is required' });
        }

        // Validate refresh token
        let decodedRefreshToken;
        try {
            decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        } catch (error) {
            return res.status(401).json({ message: 'Invalid or expired refresh token' });
        }

        // Find refresh token in the database
        const storedToken = await prisma.refreshToken.findFirst({
            where: {
                userId: decodedRefreshToken.userId,
                token: refreshToken,
                expiresAt: { gt: new Date() } // Check expiry
            }
        });

        if (!storedToken) {
            return res.status(401).json({ message: 'Refresh token invalid or expired' });
        }

        // Remove old refresh token
        await prisma.refreshToken.delete({
            where: { id: storedToken.id }
        });

        // Generate new tokens
        const accessToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            process.env.JWT_SECRET,
            { subject: 'accessApi', expiresIn: '1h' }
        );

        const newRefreshToken = jwt.sign(
            { userId: decodedRefreshToken.userId },
            process.env.REFRESH_TOKEN_SECRET,
            { subject: 'refreshToken', expiresIn: '1w' }
        );

        // Save new refresh token
        await prisma.refreshToken.create({
            data: {
                token: newRefreshToken,
                userId: decodedRefreshToken.userId,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 1 week expiry
            }
        });

        console.log("🍪 Cookies:", req.cookies)

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
            sameSite: 'Lax', // Adjust based on your needs
            path: '/', // Adjust path if needed
        });


        return res.status(200).json({
            accessToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({message: 'Access Token Expired', code: 'AccessTokenExpired'})
        }else if (error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message: 'Access Token Invalid', code: 'AccessTokenInvalid'})
        }else{
            return res.status(500).json({ message: error.message });
        }
    }
});


/** ___________________________________________________________________________________________________________________
 *                                                        ADMIN
*/

app.get('/admin', ensureAuthenticated, authorize(['ADMIN']), (req,res) => {
    return res.status(200).json({message: 'Only ADMIN can access this route'})
})

/** ___________________________________________________________________________________________________________________
 *                                                      FUNCTIONS
*/
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


function authorize(roles = []) {
    return async (req, res, next) => {
        try {
            const user = await prisma.user.findUnique({
                where: { id: req.user.id }, // Use decoded user ID
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true // Make sure to select the role
                }
            });

            if (!user || (roles.length > 0 && !roles.includes(user.role))) {
                return res.status(403).json({ message: 'Access denied' });
            }

            req.user = user; // Attach the user object to req for later use
            next(); // Continue to the next middleware
        } catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({ message: 'Internal Server Error' });
        }
    };
}

module.exports = app;
