
require('dotenv').config(); //Encryption. Important to put it right at the top.
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");

const session = require('express-session'); // Level 5.
const passport = require ('passport'); // Level 5.
const LocalStrategy = require ('passport-local'); // Level 5.
const passportLocalMongoose = require ('passport-local-mongoose'); // Level 5.
const GoogleStrategy = require('passport-google-oauth20').Strategy; // Level 6.
const findOrCreate = require('mongoose-findorcreate'); // Level 6

const app = express();

app.use(express.urlencoded({extended:true}));
app.set('view engine', 'ejs');
app.use(express.static("public"));

// Tells app to use session. Sets it up with configurations.
app.use(session({
  secret: 'Our little secret',
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize()); // Tells app to initialize passport package.
app.use(passport.session()); // Tells app to to use passport and setup session.

mongoose.connect("mongodb://localhost:27017/userDB");

// Needs to be an mongoose Schema. Javascript object doesnt work.
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose); // Hash and Salts passwords. Saves user into MongoDB database.
userSchema.plugin(findOrCreate) // Plugin for the findOrCreate module.

const User = new mongoose.model("User", userSchema);


passport.use(new LocalStrategy(User.authenticate())); // Sets up Local strategy to later authenticate localy.
// passport.serializeUser(User.serializeUser()); // Passport to serializeUser. Level 5.
// passport.deserializeUser(User.deserializeUser()); // passport to deserializeUser. Level 5.

// Level 6 serialization.
passport.serializeUser(function(user,done){
  done(null, user.id);
});

// Level 6 deserializer.
passport.deserializeUser(function(id,done){
  User.findById(id, function(err, user){
    done(err, user);
  });
});

// Sets up the google strategy which is later used to authenticate.
// Level 6. Gets the clientID and clientSecret from Google Developer Console.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // "accesToken" allows us to get the users data.
  // "profile" contains their email, google id and anything else we have acces too.
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    // Finds or create user to the database through profile.id through Google authentication.
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

// Use passport authentication using the GoogleStrategy.
app.get("/auth/google", passport.authenticate('google', {
  // Telling google that we want the google profile. Which we can use to identify them.
    scope: ['profile']
}));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    }else {
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err){
      console.log(err);
    } else {
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets")
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  // Logouts user.
  req.logout(function(err){
    if(err){
      console.log(err);
    } else {
     res.redirect("/");
    }
  });

});

app.post("/register", function(req, res){

// Register user.
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      // Authenticates user.
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets")
      })
    }
  })

});

// Checks if user is authenticated. If not: redirects to login page. Else: redirects to Secret page.
app.post("/login", passport.authenticate("local", { failureRedirect: '/login' }), function(req, res){
    res.redirect("/secrets");
});

app.listen(3000, function(){
  console.log("Server is running on port 3000.");
});
