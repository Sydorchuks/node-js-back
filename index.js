require('dotenv').config();
const bcryptjs = require('bcryptjs')
const express = require('express')
const { PrismaClient } = require('@prisma/client');
const authRoutes = require('./routes/authRoutes'); 
const jwt = require('jsonwebtoken')
const authenticatedUsers = require('./routes/authenticatedUsers')
const cors = require('cors');
const cookieParser = require('cookie-parser');


//Initialize express
const app = express()
const prisma = new PrismaClient();


app.use(cookieParser()); 
app.use(cors({
    origin: 'http://localhost:3000', // your Next.js app
    credentials: true, // allow cookies to be sent
  }));

//Configure body parses
app.use(express.json())

app.use('/api', authRoutes);
app.use('/api', authenticatedUsers);


app.get('/', (req, res) => {
    res.send('REST API Authentication and Authorization')
})


const PORT = 5000;
app.listen(PORT, async () => {
    console.log(`Server started on port ${PORT}`);

    // Test database connection
    try {
        await prisma.$connect();
        console.log('Connected to PostgreSQL database via Prisma');
    } catch (error) {
        console.error('Error connecting to database:', error);
    }

    app._router.stack.forEach((r) => {
        if (r.route && r.route.path) {
            console.log(`Registered route: ${r.route.path}`);
        }
    });
});