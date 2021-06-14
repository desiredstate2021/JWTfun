const router = require('express').Router();
const User = require('../model/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { registerValidation, loginValidation } = require('../validation');

//Validation
const Joi = require('@hapi/joi');

const schema = Joi.object({
    name: Joi.string()
    .min(6)
    .required(),
    email: Joi.string()
    .min(6)
    .required()
    .email(),
    password: Joi.string()
    .min(6)
    .required()
});



router.post('/register', async (req , res) => {

//Validate Data before USER Creation
const { error } = registerValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);

//Checking if user already exists in DBs
const emailExists = await User.findOne({email: req.body.email});
    if(emailExists) return res.status(400).send('Email Already exists');

//Hash Password
const salt = await bcrypt.genSalt(10);
const hashedPassword = await bcrypt.hash(req.body.password, salt);

//Create a new User HERE
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });
    try {
        const savedUser = await user.save()
        res.send({user: user._id });
    } catch (error) {
        res.status(400).send(err)
    }
});
 //login
router.post('/login', async (req, res) => {
const { error } = loginValidation(req.body);
if (error) return res.status(400).send(error.details[0].message);
    // check if email exists
const user = await User.findOne({email: req.body.email});
    if(!user) return res.status(400).send('Email does not exist');
    // Password Correct
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if(!validPass) return res.status(400).send('Invalid Password');

    //Create Login token
    const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
    res.header('auth-token', token).send(token);

});

module.exports = router;