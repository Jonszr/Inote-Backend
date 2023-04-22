const express = require('express');
const {userById,allusers, updateUser,deleteUser, isUser, getUserPhoto, getUserbyToken, getUserById, addFollowing, addFollower, removeFollowing, removeFollower} = require("../controllers/user");
const router =express.Router();
const {requireSignin} = require("../controllers/auth");



router.get('/users', allusers);
router.get('/user/private/:userId',requireSignin,getUserbyToken);
router.get('/user/public/:userId',getUserById);
router.put('/user/:userId',requireSignin,isUser,updateUser);
router.put('/user/add/follow',requireSignin,addFollowing,addFollower);
router.put('/user/remove/follow',requireSignin,removeFollowing,removeFollower);
router.delete('/user/:userId',requireSignin,isUser,deleteUser);
router.get('/user/photo/:userId/:photoname',getUserPhoto)
//any route containing: userId, our app will first execute userById()
router.param("userId", userById);




module.exports = router;