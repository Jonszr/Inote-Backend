const express = require('express');
const {signup,signin,signout, isAuth, resetPassword, forgotPassword} = require("../controllers/auth");
const {userById} = require("../controllers/user");
const router =express.Router();
const {userSignupValidator,passwordResetValidator } = require('../validator');


router.post('/signup',userSignupValidator,signup);
router.post('/signin',signin);
router.get('/signout',signout);
router.post('/auth',isAuth);
router.put("/forgot-password",forgotPassword);
router.put("/reset-password", passwordResetValidator,resetPassword);
//any route containing: userId, our app will first execute userById()
router.param("userId", userById);




module.exports = router;