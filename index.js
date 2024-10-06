const express = require('express');
const app = express();
const Datastore = require('nedb-promises')
const bcrypt = require('bcryptjs');
const config = require('./config');
const {authenticator} = require('otplib');
const qrCode = require('qrcode')

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
            role : role ?? 'member',
            '2faEnable' : false,
            '2faSecret' : null
        });
        return res.status(201).json({message:"User Registered Successfully"})
    }catch(err){
        return res.status(500).json({message: err.message})       
    }
});

app.get('/api/auth/login', async function(req, res){
    const refreshToken = jwt.sign({userId: user._id}, config.refreshTokenSecret, {subject: 'refreshToken', expiresIn: '1w'});
    await userRefreshTokens.insert({
        refreshToken : refreshToken,
        userId : user._id,
    });
    return res.status(200).json({
        id: user._id,
        name: user.name,
        email: user.email,
        accessToken,
        refreshToken,
    })
} );

app.post('/api/auth/refresh-token', async (req, res)=> {
    try {
        const {refreshToken} = req.body;

        if (!refreshToken) {
            return res.status(401).json({message:'Refresh Token Not Found'});
        } ;
        const decodedrefreshToken = jwt.verify(refreshToken, config.refreshTokenSecret);

        const userRefreshToken = await userRefreshTokens.findOne({
            refreshToken : refreshToken,
            userId : decodedrefreshToken.userId,
        });

        if (!userRefreshToken) {
            return res.status(401).json({message: 'Refresh Token Invalid or expired'})
        };

        await userRefreshTokens.remove({_id: userRefreshToken._id});
        await userRefreshTokens.compactDataFile()

    } catch (error) {
        if(error instanceof jwt.TokenExpiredError|| error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message: 'Refresh Token Invalid or expired'})
        }
        res.status(500).json({message:error.message})
    }
});

app.get('/api/auth/2fa/generate', ensureAuthenticated, async (req, res)=> {
    try {
        const user = await users.findOne({_id:req.user.id});

        const secret = authenticator.generateSecert();
        const uri = authenticator.keyuri(user.email, 'manfra.io', secret);

        await users.update({_id: req.user.id}, {$set:{'2faSecret':secret}});
        await users.compactDataFile();

        const  qrCode = await qrcode.toBuffer(uri, {type:'img/png', margin:1});

        res.setHeader('Content-Disposition', 'attachment: filename=qrcode.png');
        return res.status(200).type('image/png').send(qrCode)
    } catch (error) {
        return res.status(500).json({message: error.message})
    }
})

app.post('/api/auth/2fa/validate', ensureAuthenticated, async(req, res)=> {
    try {
        const {totp} = req.body;
        if(!totp) {
            return res.status(422).json({message:'TOTP is required'});
        }

        const user = await users.findOne({_id: req.user.id});

        const verified = authenticator.check(totp, user['2faSecret']);

        if(!verified) {
            return res.status(400).json({message:'TOTP is not correct or expired'});
        };

        await users.update({_id: req.user.id}, {$set:{'2fsEnable': true}});
        await users.compactDataFile();
        return res.status(200).json({message: 'TOTP validated successfully'})
    } catch (error) {
        
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

app.get('/api/admin',ensureAuthenticated,authorize(['admin']), (req, res)=>{
    return res.status(200).json({message: 'Only admin can access the route'})
});

app.get('/api/moderator',ensureAuthenticated,authorize(['admin', 'moderator']), (req, res)=>{
    return res.status(200).json({message: 'Only admins and moderators can access the route'})
})

app.get('/api/auth/logout', ensureAuthenticated, (req, res){
    // logout
})

app.post()

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