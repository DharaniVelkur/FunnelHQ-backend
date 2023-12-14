const express = require('express');
const dotenv = require('dotenv');
const app= express();
var cors = require('cors');
app.use(cors());
require('./db/conn');
const router = require('./routes/router');
dotenv.config();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const userdb = require('./models/userSchema');
const MongoStore = require('connect-mongodb-session')(session); 
app.use(express.json());

app.use(router);
//setup session middleware
app.use(session({secret:process.env.SESSION_SECRET,resave:true,saveUninitialized:true, store:new MongoStore({uri:process.env.MONGOOSE_URL,collection:"users"})}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user);
  });
  
  passport.deserializeUser((user, done) => {
    done(null, user);
  });

  // Set up Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_PASSWORD,
    callbackURL: process.env.CALLBACK_URL,
  },
 async (accessToken, refreshToken, profile, done) => {
    // Here, you can link the authenticated user with your local user database
    // You can use profile.id as a unique identifier for the user
    // For simplicity, let's assume you have a User model in your db/conn file
    // Examplce: const User = require('./db/conn').User;
    try {
        const user = await userdb.findOne({ googleId: profile.id });
        if (!user) {
          const newUser = new userdb({ googleId: profile.id });
          await newUser.save();
        }
        return done(null, profile);
      } catch (error) {
        return done(error);
      }
  }
));
  


app.listen(process.env.PORT,()=>{console.log("Server listening on port " + process.env.PORT)});