const express= require('express');
const router =new express.Router();
const passport = require('passport');
const { registeruser, loginuser, validuser, logoutuser, sendPasswordLink, verifyuser, changePassword } = require('../controllers/url');
const authenticate = require('../middleware/authenticate');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.CLIENT_ID);


router.post('/register',registeruser);
router.post('/login',loginuser);
router.get('/validuser',authenticate,validuser);
router.get('/logout',authenticate,logoutuser);
router.post('/sendpasswordlink',sendPasswordLink);
router.get("/forgotpassword/:id/:token",verifyuser)
router.post('/:id/:token',changePassword);

//redirect the user to Google for authentication
router.get('/auth/google',passport.authenticate('google', { scope: ['profile', 'email'] }));


// Callback route after Google has authenticated the user
router.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Handle successful authentication
    res.redirect('/home');
  },

  (err, req, res, next) => {
    // Handle errors during authentication
    console.error('Error during Google authentication:', err);
    res.redirect('/'); // Redirect to home or login page
  }
);

router.get('auth/checkAuth', (req, res) => {
    res.send(req.isAuthenticated() ? req.user : 'Not authenticated');
});

router.post('/google-login',async(req,res)=>{
    try {
        const {access_token} =req.body;
        //verify google token
        // const ticket = await client.verifyIdToken({
        //     idToken:access_token,
        //     audience:process.env.CLIENT_ID
        // });
        // const payload =ticket.getPayload();
        const googleResponse = await fetch(`https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${access_token}`);
        const googleData = await googleResponse.json();
    
        if (googleData.error_description) {
          throw new Error(googleData.error_description);
        }
        const {email,sub} = googleData;
        const user = { email, googleId: sub };
        const token = process.env.TOKEN;
        return res.status(200).json({ status: 200, user, token });
    } catch (error) {
        console.error('Error handling Google login:', error);
    return res.status(400).json({ status: 400, error: 'Internal Server Error' });
    }
})

module.exports= router;