import express from "express"
import { body, matchedData, validationResult } from "express-validator"
import mongoose from "mongoose"
import { hashPassword } from "./hashPassword.mjs"
import { User } from "./dbSchema/userSchema.mjs"
import passport from "passport"
import './strategies/local-strategy.mjs'
import jwt from "jsonwebtoken"
const JWT_SECRET = "my_jwt_secret"
const app = express()
app.use(express.json())
let currentUserToken = null
const PORT = process.env.PORT || 3000
mongoose.connect('mongodb://localhost/authSystem')
.then(()=>{
    console.log(`connected to Database`)
}).catch((err)=>{
    console.log(`Error :${err}`)
})
app.use(passport.initialize())
app.post('/register',
    body('username')
        .notEmpty()
        .withMessage(`username should not be empty`)
        .isLength({min:3,max:10})
        .withMessage(`username should contain at most 10 characters`)
        .isString()
        .withMessage(`username should be a string`),
    body('password')
        .notEmpty()
        .withMessage('Password should not be empty')
        .isLength({ min: 6 })
        .withMessage('Password should be at least 6 characters long'),
    body('role')
        .notEmpty()
        .withMessage('Role is required')
        .isString()
        .withMessage(`Role has to be a String`),
    async (req,res)=>{
        const result = validationResult(req)
        if(!result.isEmpty()) return res.status(400).send(result.array())
        const data = matchedData(req)
        data.password = hashPassword(data.password)
        const newUser = new User(data)
        try{
            const savedUser = await newUser.save()
            return res.status(200).send(savedUser)
        }catch(err){
            return res.status(400).send(`Error:${err}`)
        }
})

app.post('/auth', passport.authenticate("local", { session: false }), (req, res) => {
    currentUserToken = req.user.token;
    console.log(currentUserToken)
    res.json({
        user: req.user.user,
        token: req.user.token
    });
});


const pageHandler = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(401).send(`Access forbidden: Insufficient Permission`);
        }
        next();
    }
};


const authJWT = (req, res, next) => {
    if (!currentUserToken) {
        return res.status(401).json({ msg: 'No token provided so access denied' });
    }
    try {
        const decoded = jwt.verify(currentUserToken, JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (err) {
        return res.status(403).send(err);
    }
};


app.get('/admin', authJWT, pageHandler('admin'), async (req, res) => {
    res.send(`Welcome admin`);
});

app.listen(PORT,()=>{
    console.log(`Running on Port ${PORT}`)
})