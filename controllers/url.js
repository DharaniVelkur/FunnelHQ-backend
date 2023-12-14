const userdb = require("../models/userSchema");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
const Secret_key=process.env.JWTSECRET;
const nodemailer = require('nodemailer');


let transporter =nodemailer.createTransport({
    host:"smtp.gmail.com",
    service:"gmail",
    port:465,
    secure:true,
    auth:{
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
    }
})




//register user
async function registeruser(req,res){
    if(!req.body.name || !req.body.email || !req.body.password || !req.body.cpassword){
        return res.status(400).json({error:"Please fill all the fields"});
    }
    try {
        const preuser= await userdb.findOne({email:req.body.email});
        if(preuser){
           return res.status(400).json({ error: "user already exists!!" })
        } else if (req.body.password !== req.body.cpassword){
           return res.status(400).json({ error: "password and confirm password does not match" })
        } else {
            let newuser =await new userdb({
                name:req.body.name,
                email:req.body.email,
                password:req.body.password,
                cpassword:req.body.cpassword
            });
            //password hashing
            const storeddata =await newuser.save();
           return res.status(200).json({storeddata});
        }
    } catch (error) {
        res.status(400).json({ error: "Some error occurred" });
    }
}

//login user
async function loginuser(req, res) {
    if(!req.body.email||!req.body.password){
        return res.status(400).json({error:"Please fill all the fields"});
    }
    try {
        const uservalid = await userdb.findOne({email:req.body.email});
        if(uservalid){
            const ismatch = await bcrypt.compare(req.body.password, uservalid.password);
            if(!ismatch){
               return res.status(400).json({ error: "invalid details" })
            } else {
                const token = await uservalid.generateAuthtoken();
                const result = { uservalid, token }
                return res.status(200).json({ result });
            }
        } else {
            return res.status(400).json({error: "User does not exist!!!"})
        }
    } catch (error) {
        res.status(400).json({ error: "Some error occurred" });
    }
}

//valid user 
async function validuser (req,res){
    try {
        const validuserone = await userdb.findOne({ _id: req.userId });
        return res.status(200).json({ validuserone })
    } catch (error) {
        res.status(400).json({error });
    }
}

//logout user
async function logoutuser (req,res){
    try {
        req.rootUser.tokens =req.rootUser.tokens.filter(e => {
            return e.token !== req.token
        })
        req.rootUser.save();
        return res.status(200).json({message:req.rootUser});
    } catch (error) {
        return res.status(400).json(error);
    }
}

//send reset password link
async function sendPasswordLink(req,res){
    if(!req.body.email) return res.status(400).json({error:"Enter your email address"});
    try {
        const finduser = await userdb.findOne({ email: req.body.email });
        if(finduser){
            const token = jwt.sign({ _id: finduser._id }, Secret_key, {expiresIn: "120s"});
            const setusertoken = await userdb.findByIdAndUpdate(finduser._id, {
                verifytoken: token
            }, { new: true });
            if(setusertoken){
                const mailOptions ={
                    from:process.env.EMAIL,
                    to:req.body.email,
                    subject: "Password Reset Link",
                    text: `This link is valid for 2 minutes https://funnel-hq.vercel.app/forgotpassword/${finduser._id}/${setusertoken.verifytoken}`
                }
                transporter.sendMail(mailOptions,(error,info)=>{
                    if (error) {
                        res.status(400).json({ "error": "Email not sent" })
                    } else {
                        res.status(200).json({ "message": "Email sent successfully!!" })
                    }
                })
            }
        } else {
            return res.status(400).json({error:"User not found"})
        }
    } catch (error) {
        return  res.status(400).json({ error: "Some error occurred" });
    }
}

async function verifyuser(req, res) {
    const id = req.params.id;
    const token = req.params.token;
    try {
        const validuser = await userdb.findOne({ _id: id, verifytoken: token });
        const verifyToken = jwt.verify(token, Secret_key);
        if (validuser && verifyToken._id) {
            res.status(200).json({  validuser })
        } else {
            res.status(401).json({ error: "user not exist" })
        }

    } catch (error) {
        res.status(400).json({error: "some error occurred" })
    }
}

//change password
async function changePassword(req, res) {
    const id = req.params.id;
    const token = req.params.token;
    try {
        const validuser= userdb.findOne({_id:id,verifytoken:token});
        const validtoken = jwt.verify(token, Secret_key);
        if(validtoken._id &&validuser){
            const newPassword =await bcrypt.hash(req.body.password,12);
            const setnewpassword = await userdb.findByIdAndUpdate(id,{password:newPassword})
            await setnewpassword.save();
            return res.status(200).json({ setnewpassword })
        } else {
            res.status(400).json({ "error": "user not exist" })
        }
    } catch (error) {
        res.status(401).json({error: "some error occurred" });
    }
}

module.exports ={registeruser,loginuser,validuser,logoutuser,sendPasswordLink,changePassword,verifyuser};