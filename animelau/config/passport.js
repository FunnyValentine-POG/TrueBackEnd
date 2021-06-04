'use strict';

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var GoogleStrategy = require('passport-google-oauth20').Strategy;

var User = require('../models/user');
var secret = require('../secret/secret');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

passport.use('local.signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, (req, email, password, done) => {
    User.findOne({ 'email': email }, (err, user) => {
        if (err) {
            return done(err);
        }

        if (user) {
            return done(null, user, req.flash('error', 'User With Email Already Exist'));
        }

        if (req.body.password !== req.body.repassword) {
            return done(null, user, req.flash('error', 'Mật khẩu không trùng nhau'));
        }
        var newUser = new User();
        newUser.email = req.body.email;
        newUser.password = newUser.encryptPassword(req.body.password);

        newUser.save((err) => {
            return done(null, newUser);
        });
    });
}));

passport.use('local.adminsignup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, (req, email, password, done) => {
    User.findOne({ 'email': email }, (err, user) => {
        if (err) {
            return done(err);
        }

        if (user) {
            return done(null, user, req.flash('error', 'User With Email Already Exist'));
        }

        if (req.body.password !== req.body.repassword) {
            return done(null, user, req.flash('error', 'Mật khẩu không trùng nhau'));
        }

        if (req.body.code !== 'animelau') {
            return done(null, user, req.flash('error', 'Mã xác nhận không đúng'));
        }

        var newUser = new User();
        newUser.email = req.body.email;
        newUser.password = newUser.encryptPassword(req.body.password);
        newUser.role = 'admin';

        newUser.save((err) => {
            return done(null, newUser);
        });
    });
}));

passport.use('local.login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, (req, email, password, done) => {
    User.findOne({ 'email': email }, (err, user) => {
        if (err) {
            return done(err);
        }

        var messages = [];
        if (!user) {
            messages.push('Email does not exist');
            return done(null, user, req.flash('error', messages));
        }

        if (!user.validPassword(password)) {
            messages.push('Password is invalid');
            return done(null, null, req.flash('error', messages));
        }

        return done(null, user);
    });
}));

passport.use(new FacebookStrategy(secret.facebook,
    (req, token, refreshTOken, profile, done) => {
        User.findOne({ facebook: profile.id }, (err, user) => {
            if (err) {
                return done(err);
            }
            if (user) {
                return done(null, user);
            } else {
                var newUser = new User();
                newUser.facebook = profile.id;
                newUser.fullname = profile.displayName;
                newUser.email = profile._json.email;
                newUser.tokens.push({ token: token });

                newUser.save((err) => {
                    return done(null, newUser);
                });
            }
        });
    }));

passport.use(new GoogleStrategy(secret.google,
    (req, gtoken, refreshTOken, profile, done) => {
        User.findOne({ google: profile.id }, (err, user) => {
            if (err) {
                return done(err);
            }
            if (user) {
                return done(null, user);
            } else {
                var newUser = new User();
                newUser.google = profile.id;
                newUser.fullname = profile.displayName;
                newUser.email = profile._json.email;
                newUser.gtokens.push({ gtoken: gtoken });

                newUser.save((err) => {
                    return done(null, newUser);
                });
            }
        });
    }));