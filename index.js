const express = require('express');
const app = express();
const Datastore = require('nedb-promises')
const bcrypt = require('bcryptjs');
const config = require('./config');

app.use(express.json()); 

const users = Datastore.create('Users.db');
const userRefreshTokens = Datastore.create('UserRefreshTokens.db')

app.get('/', function(req, res){
    res.json({'greet': "Hello"})
})

app.post('/api/auth/register', async function(req, res){
    try{
        const {email, password, name, role} = req.body;
        if(!name || !password ||!email){
            return res.status(422).json({message :"Please fill in all fields"})
        }
        const hashedpassword = await bcrypt.hash(password, 10);
        const newUser = await users.insert({
            name,
            email,
            password : hashedpassword,
            role : role ?? 'member'
        });
        return res.status(201).json({message:"User Registered Successfully"})
    }catch(err){
        return res.status(500).json({message: err.message})       
    }
});

app.get('/api/auth/register', async function(req, res){
    const refreshToken = jwt.sign({userId: user._id}, config.refreshTokenSecret, {subject: 'refreshToken', expiresIn: '1w'})
} )

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

app.get('api/admin',ensureAuthenticated,authorize(['admin']), (req, res)=>{
    return res.status(200).json({message: 'Only admin can access the route'})
});

app.get('api/moderator',ensureAuthenticated,authorize(['admin', 'moderator']), (req, res)=>{
    return res.status(200).json({message: 'Only admins and moderators can access the route'})
})

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

function authorize(){
    return async function (req, res, next){
        const user = await users.findOne({_id:req.user.id});
        if(!user || !roles.includes(user.role)){
            return res.status(403).json({mesage:'Access denied'})
        }
        next()
    }
}

app.listen(3000, ()=>{
    console.log('Server Started at 3000');    
})