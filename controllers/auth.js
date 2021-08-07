const crypto = require('crypto')

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');

const {validationResult} = require('express-validator/check');

const User = require('../models/user');
const user = require('../models/user');

const transporter = nodemailer
  .createTransport(
    sendgridTransport({
      auth : { 
        api_key : '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'                
        }
      })
    );

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else {
    message = null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login' ,
    errorMessage : message,
    oldInput : 
      {
        email: "" , 
        password :"" 
      } ,
      validationErrors : []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else {
    message = null
  }

  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage : message,
    oldInput : 
      {
        email: "" , 
        password :"" , 
        confirmPassword : ""
      } ,
      validationErrors : []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  // validate later
  const errors = validationResult(req);
  if(!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login' ,
      errorMessage : errors.array()[0].msg ,
      oldInput : 
        {
          email: email , 
          password :password
        },
      validationErrors : errors.array()
    });
  }

  User.findOne({ email : email})
    .then(user => {
      if(!user) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login' ,
          errorMessage : 'Invalid Input' ,
          oldInput : 
            {
              email: email , 
              password :password
            },
          validationErrors : [{param: 'email' , param : 'password'}]
        });
      }
      // user exist 
      // validate password
      bcrypt
        .compare(password , user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              return res.redirect('/');
          });  
        }
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login' ,
          errorMessage : 'Invalid Input' ,
          oldInput : 
            {
              email: email , 
              password :password
            },
          validationErrors : [{param: 'email' , param : 'password'}]
        });
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login')
        });   
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postSignup = (req, res, next) => {
  //extract info from incoming request
  const email = req.body.email;
  const password = req.body.password;

  // validate later
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage : errors.array()[0].msg ,
      oldInput : 
        {
          email: email , 
          password :password , 
          confirmPassword : req.body.confirmPassword
        },
        validationErrors : errors.array()
    });
  }

      //bcrypt package
      // hash value of 12 is considered highlly secured
      return bcrypt
        .hash(password , 12)  
        .then(hashedPassword => {
          //create new user
          const user = new User ({
            email : email ,
            password : hashedPassword,
            cart : { items : [] }
          });
          return user.save();
        })
      .then(result => {
        res.redirect('/login');
        return transporter.sendMail({
          to : email ,
          from : 'sjagtap@updatusinc.com' ,
          subject : 'SignUp Success',
          html : '<h1> You Signed Up Successfuly!! </h1>'
        });  
      })
      .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      }); 
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req , res ,next) => {
  let message = req.flash('error');
  if(message.length > 0) {
    message = message[0];
  } else {
    message = null
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage : message
  });
};
 
exports.postReset = (req,res,next) => {
  crypto.randomBytes(32 , (err , buffer) => {
    if(err) {
      console.log(err);
      returnres.redirect('/reset')
    }
    const token = buffer.toString('hex');
    User
      .findOne({email : req.body.email})
      .then(user => {
        if(!user) {
          req.flash('error' , 'No Account With That Email !');
          return res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then(result => {
        res.redirect('/');
        transporter.sendMail({
          to : req.body.email ,
          from : 'sjagtap@updatusinc.com' ,
          subject : 'Password Reset',
          html : `
            <p> You requested password reset</p>
            <p> Click this<a href = "http://localhost:3000/reset/${token}"> link </a>to set new password</p>
          `
        });
      })
      .catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      });
  });
};

exports.getNewPassword = (req,res,next) => {
  //get token
  const token = req.params.token;
  User
    .findOne({
      resetToken : token , 
      resetTokenExpiration : {$gt: Date.now()}
    })
    .then(user => {
      let message = req.flash('error');
      if(message.length > 0) {
        message = message[0];
      } else {
        message = null
      }   
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'New Password',
        errorMessage : message,
        userId : user._id.toString(),
        passwordToken : token
      });
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postNewPassword = (req,res,next) => {
  //extract new password
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;

  let resetUser;
  //reset user
  User
    .findOne ({
      resetToken : passwordToken , 
      resetTokenExpiration : {$gt : Date.now()} , 
      _id : userId 
    })
    .then(user => {
      resetUser = user ;
      return bcrypt.hash(newPassword , 12) ;
    })
    .then( hashedPassword => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = null;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then(result => {
      res.redirect('/login');
    })
    .catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });

};