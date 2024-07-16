const express = require('express');
const app = express();
const {DBConnection} = require('./database/db.js');
const User = require('./models/users.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');


//middlewares
app.use(express.json());
app.use(express.urlencoded({extended: true}));
DBConnection();

app.get("/", (req, res)=>{
    res.send("Welcome to today's class!");
});

app.get("/home", (req, res)=>{
    res.send("Welcome Home!");
});

app.post("/register", async(req, res)=>{
    {
        try{
            //get all the data from the request body
            const {firstname, lastname, email, password} = req.body; 
            //const firstname = req.body.firstname;


            //check that all the data should exist
            if(!(firstname && lastname && email && password)){
                return res.status(400).send("Please enter all the details!");
            }

            //check if user already exists
            const existingUser = await User.findOne({email});
            if(existingUser){
                return res.status(400).send("User already exists!");
            }

            //encrypyt the password
            const hashPassword = bcrypt.hashSync('password', 12);
            console.log(hashPassword);

            //save the data to the userbase
            const user = await User.create({
                firstname,
                lastname,
                email,
                password: hashPassword,
            });

            //generate a token for user and send it
            const token = jwt.sign({id: user._id, email}, process.env.SECRET_KEY, {
                expiresIn: "1h"
            });

            user.token = token;
            user.password = undefined;

            //send the response
            res.status(201).json({
                message: "You have successfully registered!",
                success: true,
                user, 
                token
            })
        }
        catch (error){
            console.error(error);
        }
    }
})

app.get("/login", async(req, res)=>{
    {
        try {
            //get all the data from the request body
            const {email, password} = req.body; 

            //check that all the data should exist
            if(!(email && password)){
                return res.status(400).send("Please enter all the details!");
            }

            //find the user in the database
            const user = await User.findOne({email});
            if(!user)
            {
                return res.status(401).send("User not found!");
            }

            //match the password
            const enteredPassword = await bcrypt.compare(password, user.password);
            if(!enteredPassword){
                return res.status(401).send("Password is incorrect.");
            }

            //generate the token
            const token = jwt.sign({id: user.id}, process.env.SECRET_KEY, {
                expiresIn: "1d"
            });
            user.token = token;
            user.password = undefined;

            //store cookies
            const options = {
                expires: new Date(Date.now() + 1*24*60*60*1000),
                httpOnly: true //only manipulate by server not by client/user
            };

            //send the token
            res.status(200).cookie("token", token, options).json({
                message: "You have successfully logged in!",
                success: true,
                token
            });
        } 
        catch (error) {
            console.error(error);
        }
    }
});


app.listen(8000, ()=>{
    console.log("Server is listening on port 8000");
});




