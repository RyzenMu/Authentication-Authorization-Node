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

app.listen(3000, ()=>{
    console.log('Server Started');    
})