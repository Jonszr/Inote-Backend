const express = require('express');
const app = express();
const mongoose = require('mongoose');
const morgan = require("morgan");
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')
const expressValidator =require('express-validator');
dotenv.config(); 
//bring in routes
const postRoutes = require('./routes/post');
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");

mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true})
.then(()=> console.log('DB Connected'));

mongoose.connection.on ("error",err => {
    console.log(`DB connection error: ${err.message}`);
});
// const myOwnMiddleware = (req,res,next) => {console.log("middleware applied!");
// next();};
//middleware;
app.use(express.static('public'))
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(expressValidator());
// app.use(myOwnMiddleware);
app.use("/blog", postRoutes);
app.use("/blog", authRoutes);
app.use("/blog", userRoutes);
app.use(function (err,req,res,next){
    if(err.name === "UnauthorizedError"){
        res.status(401).json({error: "Unauthorized!"});
    }
})

const port = process.env.PORT || 8080;
app.listen(port,()=>{
    console.log(`A Node Js API listening on port: ${port}`);
});
