const express = require('express');
const app = express();
const Datastore = require('nedb-promises')
const bcrypt = require('bcryptjs');

app.use(express.json()); 

const users = Datastore.create('Users.db');

app.get('/', function(req, res){
    res.json({'greet': "Hello"})
})

app.post('/api/auth/register', async function(req, res){
    try{
        const {email, password, name} = req.body;
        if(!name || !password ||!email){
            return res.status(422).json({message :"Please fill in all fields"})
        }
        const hashedpassword = await bcrypt.hash(password, 10);
        const newUser = await users.insert({
            name,
            email,
            password : hashedpassword
        });
        return res.status(201).json({message:"User Registered Successfully"})
    }catch(err){
        return res.status(500).json({message: err.message})       
    }
})

app.get('api/auth/current',ensureAuthenticated, async (req, res) => {
    try {
        const user = await users.findOne({_id: req.user.id});
        return res.status(200).json({
            id: user._id,
            name: user.name,
            email: user.email
        })
    } catch (error) {
        return res.status(401).json({message: error.message});
    }
}); 

async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization;
    if (!accessToken) {
        return res.status(401).json({message : 'Access Token Not Found'});
    }
    try {
        const decodedAccessToken = jwt.verify(accessToken, config.accessTokenSecret);
        req.user = {id: decodedAccessToken.userId};
        next();
    } catch (error) {
        return res.status(401).json({message : 'Access token invalid or expired'});
    }
}

app.listen(3000, ()=>{
    console.log('Server Started at 3000');    
})