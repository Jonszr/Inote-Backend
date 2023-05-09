const jwt = require("jsonwebtoken");
require("dotenv").config();
const expressJwt = require("express-jwt");
const User = require("../models/user");
const { sendEmail } = require("../tools/mailService");
const fs = require("fs");
const { CLIENT_RENEG_LIMIT } = require("tls");
const _ = require("lodash");

exports.signup = async (req, res) => {
  const userExists = await User.findOne({ email: req.body.email });
  if (userExists)
    return res.status(403).json({
      error: "Email is taken!",
    });
  const user = await new User(req.body);
  await user.save();

  // Email service
  const { email } = req.body;
  const emailData = {
    from: "noreply@inote.com <noreply@inote.com>",
    to: email,
    subject: `Sign up successful!! Welcome ${user.name}`,
    text: "Sign up successful!!",
    html: "Sign up successful!!",
  };
  sendEmail(emailData);

  res.status(200).json({ message: "Signup success! Please login." });
};

exports.signin = (req, res) => {
  //find the user based on email
  const { email, password } = req.body;
  User.findOne({ email })
    .populate("photo", "photoURL")
    .exec((err, user) => {
      //if err or no user
      if (err || !user) {
        return res.status(401).json({
          error: "User with that email does not exist. Please signup.",
        });
      }
      //if user is found make sure the email and password match
      //create authenicate method in model and use here
      if (!user.authenticate(password)) {
        return res.status(401).json({
          error: "Email and password do not match",
        });
      }
      user.hashed_password = undefined;
      user.salt = undefined;
      user.__v = undefined;
      user.photo.data = undefined;
      console.log(user);

      //generate a token with user id and secret
      jwt.sign(
        { user },
        process.env.JWT_SECRET,
        { expiresIn: "24h" },
        (err, data) => {
          if (err) {
            return res.status(404).json(err);
          }
          return res.json({
            token: data,
            user,
            exp: Date.now() + 1000 * 60 * 60 * 10,
          });
        }
      );
    });
};

exports.signout = (req, res) => {
  res.clearCookie("token");
  console.log(res.headers["authorization"]);
  return res.json({ message: "Signout success!" });
};

exports.requireSignin = expressJwt({
  //if the token is vaild, express jwt appends the verified users id
  // in an auth key to the request object
  secret: process.env.JWT_SECRET,
  algorithms: ["HS256"], // added later
  userProperty: "auth",
});

exports.isAuth = (req, res) => {
  // console.log(req.body)
  try {
    const token = req.body.token;
    // console.log(req.body)
    if (!token) {
      res.status(401).json({
        message: "token not found",
      });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
      if (err) return res.status(403).json({ err });
      console.log(data);
      User.findById(data.user._id)
        .populate("following", "_id name")
        .populate("followers", "_id name")
        .exec((err, user) => {
          if (err || !user) {
            return res.status(400).json({
              error: err,
            });
          }
          user.hashed_password = undefined;
          user.salt = undefined;
          user.photo.data = undefined;
          return res.json({ user });
        });
    });
  } catch (error) {
    console.log("This is a error:", error);
    return res.status(400).json({
      error,
    });
  }
  
  
};

// add forgotPassword and resetPassword methods
exports.forgotPassword = (req, res) => {
    if (!req.body) return res.status(400).json({ message: "No request body" });
    if (!req.body.email)
      return res.status(400).json({ message: "No Email in request body" });

    console.log("forgot password finding user with that email");
    const { email } = req.body;
    console.log("signin req.body", email);
    // find the user based on email
    User.findOne({ email }, (err, user) => {
      // if err or no user
      if (err || !user)
        return res.status("401").json({
          error: "User with that email does not exist!",
        });

      // generate a token with user id and secret
      const token = jwt.sign(
        { _id: user._id, iss: "NODEAPI" },
        process.env.JWT_SECRET
      );

      // email data
      const emailData = {
        from: "noreply@node-react.com",
        to: email,
        subject: "Password Reset Instructions",
        text: `Please use the following link to reset your password: ${process.env.CLIENT_URL}/reset-password/${token}`,
        html: `<p>Please use the following link to reset your password:</p> <p>${process.env.CLIENT_URL}/auth/reset-password/${token}</p>`,
      };

      return user.updateOne({ resetPasswordLink: token }, (err, success) => {
        if (err) {
          return res.json({ message: err });
        } else {
          sendEmail(emailData);
          return res.status(200).json({
            message: `Email has been sent to ${email}. Follow the instructions to reset your password.`,
          });
        }
      });
    });
  };

  // to allow user to reset password
  // first you will find the user in the database with user's resetPasswordLink
  // user model's resetPasswordLink's value must match the token
  // if the user's resetPasswordLink(token) matches the incoming req.body.resetPasswordLink(token)
  // then we got the right user

  exports.resetPassword = (req, res) => {
    const { resetPasswordLink, newPassword } = req.body;
    User.findOne({ resetPasswordLink }, (err, user) => {
      // if err or no user
      if (err || !user)
        return res.status("401").json({
          error: "Invalid Link!",
        });

      const updatedFields = {
        password: newPassword,
        resetPasswordLink: "",
      };

      user = _.extend(user, updatedFields);
      user.updated = Date.now();

      user.save((err, result) => {
        if (err) {
          return res.status(400).json({
            error: err,
          });
        }
        res.json({
          message: `Great! Now you can login with your new password.`,
        });
      });
    });
  };