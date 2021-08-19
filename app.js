//PATH :  provides utilities for working with file and directory paths
const path = require("path");

// EXPRESS : Is Node.js web application framework that provides a robust set of features for web and mobile application
const express = require("express");

//BODY-PARSER : Parse incoming request bodies in a middleware before your handlers, available under the req.body property.
const bodyParser = require("body-parser");

// MONGODB : object relation mapping (ORM)
//MONGOOSE : Is an Object Data Modeling (ODM) library for MongoDB and Node.js. 
//It manages relationships between data, provides schema validation, and is used to translate between objects in code and the representation of those objects in MongoDB
const mongoose = require("mongoose");

//Create a session middleware with the given options.
//Note Session data is not saved in the cookie itself, just the session ID. Session data is stored server-side.
const session = require("express-session");

//MongoDBStore : class that can be used to store sessions in MongoDB.
const MongoDBStore = require("connect-mongodb-session")(session);

//csurf : middleware for CSRF token creation and validation
//Cross site request forgery (CSRF)
const csrf = require("csurf");

//flash is a special area of the session used for storing messages and displaying to user
const flash = require("connect-flash");

//Multer is a node.js middleware for handling multipart/form-data, which is primarily used for uploading files
const multer = require("multer");

//import error controller file to handel error : 404: Not Found & 500:Internal Server Error
const errorController = require("./controllers/error");

//import user model : which contain user schema for mongo db: mongoose
const User = require("./models/user");

// URI : Uniform Resource Identifier
// MONGODB_URI is the connection string
const MONGODB_URI =
  "mongodb+srv://ruchita:saurabh@cluster0.t1cyv.mongodb.net/shop";

  //before using anything, we will have to initialize our app to use express
const app = express();

// MongoDBStore : used to store sessions in MongoDB
const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: "sessions",
});

// setup route middlewares
const csrfProtection = csrf();

// store image file : which user entered : into destination folder : images
// name of the file : will be DATE-OriginalName
const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "images");
  },
  filename: (req, file, cb) => {
    cb(null, new Date().toDateString() + "-" + file.originalname);
  },
});

//fiter image file .. see if its .png , .jpg or .jpeg
const fileFilter = (req, file, cb) => {
  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg"
  ) {
    cb(null, true);
  } else {
    //return invalid
    cb(null, false);
  }
};

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "./views"));

const adminRoutes = require("./routes/admin");
const shopRoutes = require("./routes/shop");
const authRoutes = require("./routes/auth");

//To load the middleware function, call app.use()

app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  multer({ storage: fileStorage, fileFilter: fileFilter }).single("image")
);

app.use(express.static(path.join(__dirname, "public")));
app.use("/images", express.static(path.join(__dirname, "images")));

//we will have to initialize our session before initializing our session store.
// initialize our session with a secret session key
app.use(
  session({
    secret: "my secret",
    resave: false,
    saveUninitialized: false,
    store: store,
  })
);

// use CSRF middelware
app.use(csrfProtection);
// use flash middelware
app.use(flash());

//pass loggedIn status to session
// pass csrf token
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// check if user have session 
// if not return user to next middelware
app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then((user) => {
      if (!user) {
        return next();
      }
      req.user = user;
      next();
    })
    .catch((err) => {
      next(new Error(err));
    });
});

// middeleware to add admin , shop and auth routes
app.use("/admin", adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

//middleware function call
app.get("/500", errorController.get500);

app.use(errorController.get404);

// error handeling middleware
app.use((error, req, res, next) => {
  //res.redirect('/500');
  res.status(500).render("500", {
    pageTitle: "Error!!!",
    path: "/500",
    isAuthenticated: req.session.isLoggedIn,
  });
});

// connect to MongoDBdatabase via mongoose 
mongoose
  .connect(MONGODB_URI)
  .then((result) => {
    app.listen(3000);
  })
  .catch((err) => {
    console.log(err);
  });
