const Post = require('../models/post');
const formidable = require('formidable');
const fs = require('fs');
const _ = require("lodash");
const user = require('../models/user');

exports.postById = (req, res, next, id) => {
    Post.findById(id).populate("postedBy", "_id name")
        .exec((err, post) => {
            
            if (err || !post) {
                return res.status(400).json({
                    error: 'post not Found'
                });
            }
            req.post = post;
            next();
        });
}

exports.getPosts = (req, res) => {
    const posts = Post.find().populate("postedBy", "_id name")
        .select("_id title body created photo")
        .sort({created:-1})
        .then((posts) => {
            posts.forEach((post)=>{
                post.photo.data = undefined;
            })
            res.json(posts);
        })
        .catch(err => console.log(err));
};

exports.getPostByPostId = (req,res) =>{
    if(req.post){
        return res.status(200).json({
            post:req.post
        })
    }

    return res.status(404).json({
        msg:'post not Found'
    })
}

exports.createPost = (req, res, next) => {
    let form = new formidable.IncomingForm();
    form.keepExtensions = true;
    form.parse(req, (err, fields, files) => {
        if (err) {
            return res.status(400).json({
                error: "Image could not be uploaded"
            });
        }
        let post = new Post(fields);
        req.profile.hashed_password = undefined;
        req.profile.salt = undefined;
        req.profile.photo = undefined;
        req.profile.created=undefined;
        
        post.postedBy = req.profile
        
        if (files.photo) {
            const protocol = req.protocol
            const host = req.hostname
            post.photo.data = fs.readFileSync(files.photo.filepath)
            post.photo.contentType = files.photo.mimetype;
            
            const filename = files.photo.originalFilename;
            post.photo.photoURL = `${protocol}://${host}:${process.env.PORT}/blog/post/photo/${post._id}/${filename}`;

           
        }
        post.save((err, result) => {
            if (err) {
                return res.status(400).json({
                    error: err
                })
            }
            result.photo.data = undefined;
            return res.status(200).json({result,message:'created successfully!'});
        });
    });
}

exports.getPostPhoto = (req,res) => {
    const photo = req.post.photo;
    console.log('photo')
    if (photo.data) {
        console.log('photo here')
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

exports.privatePostedByUser = (req, res) => {
    Post.find({ postedBy: req.profile._id })
        .populate("postedBy", "_id name")
        .sort({created:-1})
        .exec((err, posts) => {
            if (err) {
                return res.status(400).json({
                    error: err
                })
            }
            res.json(posts);
        })
}
exports.publicPostedByUser = (req, res) => {
    Post.find({ postedBy: req.profile._id })
        .populate("postedBy", "_id name")
        .sort({created:-1})
        .exec((err, posts) => {
            if (err) {
                return res.status(400).json({
                    error: err
                })
            }
            posts.forEach((post)=>{
                post.photo.data = undefined
                post.__v = undefined
            })
            res.json(posts);
        })
}

exports.deletePost = (req, res) => {
    
    let post = req.post;
    if (!post) {
        res.status(400).json({
            message: 'post not found'
        })
    }
    post.remove((err, post) => {
        if (err) {
            return res.status(400).json({
                error:err
            })
        }
        res.json({
            message: 'Post deleted successfully!'
        });
    })
}
exports.updatePost = (req, res) => {
    let form = new formidable.IncomingForm();
    form.keepExtensions = true;
    form.parse(req, (err, fields, files) => {
        if (err) {
            res.status(400).json({
                error: err
            })
        }
        let post = req.post;


        if (files.photo) {
            post.photo.data = fs.readFileSync(files.photo.path)

            post.photo.contentType = files.photo.type
        }
        post.updated = Date.now();
        post = _.extend(post, fields);

        post.save((err, result) => {
            if (err) {
                return res.status(400).json({
                    err
                })
            }
            return res.json({
                result,
                message: 'Update post successfully!'
            });
        });
    });
}


exports.isPoster = (req, res, next) => {
    // console.log(req.post)
    console.log(req.post)
    console.log(req.post.postedBy._id)
    let sameUser = false;
    let adminUser = false;
    try {
        sameUser = req.post && req.auth.user && req.post.postedBy && req.post.postedBy._id == req.auth.user._id;
        adminUser = req.post && req.auth && req.auth.user.role === 'admin';
    } catch (error) {
        console.log(error)
        return res.status(404).json({
            error
        })
    }



    let isPoster = sameUser || adminUser;


    if (!isPoster) {
        return res.status(403).json({
            error: "User is not authorized"
        })
    }
    next();
}

exports.comment = (req, res) => {
    comment = req.body.comment;
    comment.postedBy = req.body.userId;
  
    Post.findByIdAndUpdate(
      req.body.postId,
      { $push: { comments: comment } },
      { new: true }
    )
      .populate("comments.postedBy", "_id name")
      .populate("postedBy", "_id name")
      .exec((err, result) => {
        if (err) {
          return res.status(400).json({
            error: err,
          });
        } else {
          res.json(result);
        }
      });
  };

exports.uncomment = (req, res) => {
    let comment = req.body.comment;
  
    Post.findByIdAndUpdate(
      req.body.postId,
      { $pull: { comments: { _id: comment._id } } },
      { new: true }
    )
      .populate("comments.postedBy", "_id name")
      .populate("postedBy", "_id name")
      .exec((err, result) => {
        if (err) {
          return res.status(400).json({
            error: err,
          });
        } else {
          res.json(result);
        }
      });
  };

  exports.updateComment = (req, res) => {
    let comment = req.body.comment;

    Post.findByIdAndUpdate(req.body.postId, {
      $pull: { comments: { _id: comment._id } },
    }).exec((err, result) => {
      if (err) {
        return res.status(400).json({
          error: err,
        });
      } else {
        Post.findByIdAndUpdate(
          req.body.postId,
          { $push: { comments: comment, updated: new Date() } },
          { new: true }
        )
          .populate("comments.postedBy", "_id name")
          .populate("postedBy", "_id name")
          .exec((err, result) => {
            if (err) {
              return res.status(400).json({
                error: err,
              });
            } else {
              res.json(result);
            }
          });
      }
    });
  };