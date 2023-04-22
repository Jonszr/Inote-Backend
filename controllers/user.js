const _ = require("lodash");
const User = require("../models/user");
const formidable = require("formidable");
const fs = require("fs");


exports.userById = (req, res, next, id) => {
    User.findById(id).populate('following','_id name').populate('followers','_id name').exec((err, user) => {
        if (err || !user) {
            console.log('wocao')
            return res.status(400).json({
                error: "User not found",
            });
        }

        user.__v= undefined;

        req.profile = user;
        next();
    });
};

exports.isUser = (req, res, next) => {
    console.log(req.auth.user._id)
    const authorized = req.profile && req.auth && req.profile._id == req.auth.user._id;


    if (!authorized) {
        return res.status(403).json({
            error: "User is not authorized to perform this action",
        });
    }
    next();
};


exports.getUserPhoto = (req, res, next) => {
    const photo = req.profile.photo;

    if (photo.data) {
        // res.set({"Content-Type",photo.contentType})
        res.set({
            'Content-Type': photo.contentType
        })

        return res.send(photo.data);
    }else{
        return res.status(404).json({
            error:'photo not found'
        })
    }
  
}


exports.allusers = (req, res) => {
    User.find((err, users) => {
        if (err) {
            return res.status(400).json({
                error: err,
            });
        }
        res.json({ users });
    }).select("name email updated created");
};
exports.getUserbyToken = (req, res) => {
    req.profile.hashed_password = undefined;
    req.profile.salt = undefined;
    req.profile.photo.data = undefined;
    return res.json(req.profile);
};
exports.getUserById = (req, res) => {
    req.profile.hashed_password = undefined;
    req.profile.salt = undefined;
    req.profile.photo.data = undefined;
    req.profile.role = undefined;
    return res.json(req.profile);
}

exports.updateUser = (req, res, next) => {
    let form = new formidable.IncomingForm();
    form.keepExtensions = true;
    form.parse(req, (err, fields, files) => {



        if (err) {
            return res.status(400).json({
                error: "Image could not be uploaded",
            });
        }
        let user = req.profile;
        try {

            if (files.photo) {
                const protocol = req.protocol
                const host = req.hostname
                user.photo.data = fs.readFileSync(files.photo.filepath);
                user.photo.contentType = files.photo.mimetype;
                console.log(files.photo.originalFilename)
                const filename = files.photo.originalFilename;
                user.photo.photoURL = `${protocol}://${host}:${process.env.PORT}/blog/user/photo/${user._id}/${filename}`
                console.log(`${protocol}://${host}:${process.env.PORT}/blog/user/photo/${user._id}/${filename}`);
            }

        } catch (error) {
            console.log(error)
        }

        user = _.extend(user, fields);
        user.updated = Date.now();
        user.save((err) => {
            if (err) {
                return res.status(400).json({
                    error: "You are not authorized to perform this action",
                });
            }
            user.hashed_password = undefined;
            user.salt = undefined;
            user.photo.data = undefined;
            res.json({ user, msg: "update successfully!" });
        });

    });
    // let user = req.profile;
    // user = _.extend(user,req.body);
    // // extend -mute the source the source object
    // user.updated =Date.now();
    // user.save((err)=> {
    //     if(err) {
    //         return res.status(400).json({
    //             error:"You are not authorized to perform this action"
    //         })
    //     }
    // user.hashed_password = undefined;
    // user.salt = undefined;
    // res.json({user});
    // });
};

exports.deleteUser = (req, res, next) => {
    let user = req.profile;
    user.remove((err, user) => {
        if (err) {
            return res.status(400).json({
                error: err,
            });
        }
        res.json({
            message: "User deleted successfully",
        });
    });
};
 exports.addFollowing = (req,res,next) => {
    User.findByIdAndUpdate(req.auth.user._id,{$push:{following:req.body.followId}},(err,result)=>{
        if(err){
            console.log('usernotfound')
            return res.status(400).json({
                error:err
            })
        }
        next();
    })
 }

 exports.addFollower = (req, res) => {
    User.findByIdAndUpdate(req.body.followId, { $push: { followers: req.auth.user._id } }, { new: true })
        .populate('following', '_id name')
        .populate('followers', '_id name')
        .exec((err, result) => {
            if (err) {
                console.log('fowllow user notfound')
                return res.status(400).json({
                    error: err
                });
            }
            result.hashed_password = undefined;
            result.salt = undefined;

            result.photo.data = undefined;
            
            res.json(result);
        });
};

exports.removeFollowing = (req,res,next) => {
    User.findByIdAndUpdate(req.auth.user._id,{$pull:{following:req.body.unfollowId}},(err,result)=>{
        if(err){
            return res.status(400).json({
                error:err
            })
        }
        next();
    })
 }

 exports.removeFollower = (req, res) => {
    User.findByIdAndUpdate(req.body.unfollowId, { $pull: { followers: req.auth.user._id } }, { new: true })
        .populate('following', '_id name')
        .populate('followers', '_id name')
        .exec((err, result) => {
            if (err) {
                return res.status(400).json({
                    error: err
                });
            }
            result.hashed_password = undefined;
            result.salt = undefined;

            result.photo.data = undefined;
            
            res.json(result);
        });
};